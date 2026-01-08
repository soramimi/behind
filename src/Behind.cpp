#include "Behind.h"
#include "Logger.h"
#include "TransactionIdGenerator.h"
#include "misc.h"
#include "network.h"
#include "rwfile.h"
#include <algorithm>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits>
#include <netdb.h>
#include <netinet/in.h>
#include <numeric>
#include <stdint.h>
#include <string.h>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

#define stricmp(A, B) strcasecmp(A, B)
#define STRERROR(S) (std::string(S) + strerror(errno))
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket(S) close(S)

#define DNS_CLASS_IN 1

std::string randomize_case(std::string qname)
{
	for (size_t i = 0; i < qname.size(); i++) {
		if (isalpha((unsigned char)qname[i])) {
			if (rand() & 0x4000) {
				qname[i] ^= 0x20;
			}
		}
	}
	return qname;
}

struct Behind::dns_record_t {
	DNS_TYPE type = DNS_TYPE::A;
	uint8_t addr[16] = {0};

	std::string to_string() const
	{
		char buf[INET6_ADDRSTRLEN];
		if (type == DNS_TYPE::A) {
			struct in_addr *in4 = (struct in_addr *)addr;
			if (inet_ntop(AF_INET, in4, buf, sizeof(buf))) {
				return buf;
			}
		} else if (type == DNS_TYPE::AAAA) {
			struct in6_addr *in6 = (struct in6_addr *)addr;
			if (inet_ntop(AF_INET6, in6, buf, sizeof(buf))) {
				return buf;
			}
		}
	}
};

struct Behind::dns_header_t {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

struct Behind::query_t {
	uint16_t upstream_id;
	uint16_t requester_id;
	uint64_t time;
	DNS_TYPE type = DNS_TYPE::A;
	sa_family_t client_family = AF_INET;
	union {
		sockaddr_in client_sa4;
		sockaddr_in6 client_sa6;
	};
	std::string request_name;
	std::string forward_name;
};

struct Behind::question_t {
	std::string name;
	DNS_TYPE type;
	uint16_t clas;
};

struct Behind::answer_t {
	std::string name;
	DNS_TYPE type;
	uint16_t clas;
	uint32_t ttl;
	std::vector<char> data;
};

class Behind::dns_cache_t {
public:
	struct Item {
		std::string key;
		uint64_t timestamp = 0;
		std::vector<Behind::dns_record_t> records;
	};
private:
	std::vector<Item> items_;
	std::unordered_map<std::string, size_t> index_;
	std::string make_key(std::string const &name) const
	{
		return misc::strtolower(name);
	}
public:
	std::vector<Behind::dns_record_t> const *find(std::string const &name)
	{
		auto key = make_key(name);
		auto it = index_.find(key);
		if (it != index_.end()) {
			auto now = misc::get_tick_count();
			if (now - items_[it->second].timestamp < 5 * 60 * 1000) { // 5 minutes
				return &items_[it->second].records;
			}
		}
		return nullptr;
	}
	void insert(std::string const &name, std::vector<Behind::dns_record_t> const &records)
	{
		auto now = misc::get_tick_count();
		auto key = make_key(name);
		auto it = index_.find(key);
		if (it == index_.end()) {
			size_t n = items_.size();
			if (n >= 4096) {
				std::sort(items_.begin(), items_.end(), [](Item const &l, Item const &r){
						return l.timestamp > r.timestamp; // newest first
						});
				while (n > 0) {
					if (now - items_[n - 1].timestamp < 5 * 60 * 1000) {
						break;
					}
					n--;
				}
				n = std::min(n, size_t(4000));
				items_.resize(n);
				index_.clear();
				for (size_t i = 0; i < n; i++) {
					index_[items_[i].key] = i;
				}
			}
			it = index_.insert(index_.end(), std::pair<std::string, size_t>(key, n));
			items_.emplace_back();
		}
		Item *item = &items_[it->second];
		item->key = key;
		item->timestamp = now;
		item->records = records;
	}
};

struct Behind::Private {
	Option option;
	TransactionIdGenerator txid_gen;
	InetResolver resolver;
	int ttl;
	// std::unordered_set<std::string> nxdomain_list;
	struct {
		Behind::dns_cache_t a;
		Behind::dns_cache_t aaaa;
	} dns_cache;
	std::vector<query_t> queries;
	Forwarder forwarder;

	struct D {
		int sock4;
		int sock6;
		struct sockaddr_in sa4;
		struct sockaddr_in6 sa6;
	};
};

Behind::Behind(const Option &opt)
	: m(new Private())
{
	m->option = opt;

	init_ttl();
	init_forwarder();

	add_nxdomain("doubleclick.net");
}

Behind::~Behind()
{
	delete m;
}

void Behind::add_nxdomain(std::string const &domain)
{
	// m->nxdomain_list.insert(domain);
}

bool Behind::eqi(const std::string &l, const std::string &r)
{
	return stricmp(l.c_str(), r.c_str()) == 0;
}

uint16_t Behind::listen_port() const
{
	return 5300;
}

int Behind::ttl() const
{
	return m->ttl;
}

void Behind::write(std::vector<char> *out, char c)
{
	out->push_back(c);
}

void Behind::write(std::vector<char> *out, const char *src, int len)
{
	if (src && len > 0) {
		out->insert(out->end(), src, src + len);
	}
}

void Behind::write_us(std::vector<char> *out, uint16_t v)
{
	v = htons(v);
	write(out, (char const *)&v, 2);
}

void Behind::write_ul(std::vector<char> *out, uint32_t v)
{
	v = htonl(v);
	write(out, (char const *)&v, 4);
}

void Behind::write_name(std::vector<char> *out, const std::string &name)
{
	char const *name_begin = name.c_str();
	char const *name_end = name_begin + name.size();
	char const *srcptr = name_begin;
	while (srcptr < name_end) {
		char const *dot = strchr(srcptr, '.');
		int len = (dot ? dot : name_end) - srcptr;
		if (len < 1 || len > 63) {
			return;
		}
		write(out, (char)len);
		write(out, srcptr, len);
		if (!dot) {
			break;
		}
		srcptr += len + 1;
	}
	write(out, (char)0);
}

int Behind::decode_name(const char *begin, const char *end, const char *ptr, std::vector<char> *out)
{
	if (begin && ptr && begin <= ptr && ptr < end) {
		char const *start = ptr;
		if ((*ptr & 0xc0) == 0xc0) {
			if (ptr + 1 < end) {
				int o = ((ptr[0] & 0x3f) << 8) | (ptr[1] & 0xff);
				decode_name(begin, end, begin + o, out);
				ptr += 2;
			}
		} else {
			while (ptr < end) {
				int len = *ptr & 0xff;
				ptr++;
				if (len == 0 || len > 63) {
					break;
				}
				if (!out->empty()) {
					out->push_back('.');
				}
				out->insert(out->end(), ptr, ptr + len);
				ptr += len;
			}
		}
		if (ptr < start || ptr > end) {
			ptr = end;
		}
		return ptr - start;
	}
	return 0;
}

int Behind::decode_name(const char *begin, const char *end, const char *ptr, std::string *name)
{
	std::vector<char> tmp;
	tmp.reserve(100);
	int n = decode_name(begin, end, ptr, &tmp);
	if (n > 0 && !tmp.empty()) {
		char const *p = &tmp[0];
		name->assign(p, tmp.size());
		return n;
	}
	return 0;
}

void Behind::write_dns_header(std::vector<char> *out, uint16_t id, uint16_t flags, uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount)
{
	uint16_t tmp[6];
	tmp[0] = htons(id);
	tmp[1] = htons(flags);
	tmp[2] = htons(qdcount);
	tmp[3] = htons(ancount);
	tmp[4] = htons(nscount);
	tmp[5] = htons(arcount);
	write(out, (char const *)tmp, 12);
}

void Behind::write_dns_question_rr(std::vector<char> *out, const std::string &name, DNS_TYPE type, uint16_t clas)
{
	write_name(out, name);
	write_us(out, (uint16_t)type);
	write_us(out, clas);
}

void Behind::write_dns_answer_rr(std::vector<char> *out, const std::string &name, uint16_t clas, uint32_t ttl, const Behind::dns_record_t &item)
{
	int len = 0;
	if (item.type == DNS_TYPE::A) {
		len = 4;
	} else if (item.type == DNS_TYPE::AAAA) {
		len = 16;
	} else {
		return;
	}
	write_name(out, name);
	write_us(out, (int)item.type);
	write_us(out, clas);
	write_ul(out, ttl);
	write_us(out, len);
	write(out, (char const *)item.addr, len);
}

int Behind::parse_question_section(const char *begin, const char *end, const char *ptr, Behind::question_t *out)
{
	int n = decode_name(begin, end, ptr, &out->name);
	if (n > 0 && !out->name.empty()) {
		char const *start = ptr;
		ptr += n;
		uint16_t tmp[2];
		memcpy(tmp, ptr, 4);
		ptr += 4;
		out->type = (DNS_TYPE)ntohs(tmp[0]);
		out->clas = ntohs(tmp[1]);
		return ptr - start;
	}
	return 0;
}

Forwarder Behind::get_forwarder()
{
	return m->forwarder;
}

size_t parse_space(char const *p)
{
	size_t i = 0;
	while (p[i]) {
		int c = (unsigned char)p[i];
		if (!isspace(c)) return i;
		i++;
	}
	return i;
}

size_t parse_int(char const *p, int *out)
{
	unsigned long int val = 0;
	size_t i = 0;
	while (p[i]) {
		int c = (unsigned char)p[i];
		if (!isdigit(c)) break;
		val = val * 10 + (c - '0');
		if (val > std::numeric_limits<int>::max()) {
			return 0;
		}
		i++;
	}
	*out = (int)val;
	return i;
}

void Behind::init_forwarder()
{
	// std::string name = "8.8.8.8";
	// std::string name = "2001:4860:4860::8888";
	// std::string name = "2a10:50c0::ad1:ff";
	// std::string name = "2a10:50c0::ad2:ff";
	std::string name = m->option.forward_addr;

	char const *host_begin = name.c_str();
	char const *host_end = host_begin + name.size();

	Forwarder forwarder;

	// detect address type
	char const *p = name.c_str();
	bool in4 = true;
	bool in6 = true;
	bool bracket = false;
	int dots = 0;
	p += parse_space(p);
	while (*p) {
		int c = (unsigned char)*p++;
		if (c == ']') {
			host_end = p - 1;
			in4 = false;
			if (!bracket) {
				in6 = false;
				break;
			}
			if (*p == ':') {
				break;
			}
			break;
		} else if (c == '[') {
			host_begin = p;
			bracket = true;
			in4 = false;
		} else if (isdigit(c)) {
			// ok
		} else if (isxdigit(c)) {
			in4 = false;
		} else if (c == ':') {
			if (in4) {
				if (dots == 3) {
					host_end = p;
					break;
				}
				in4 = false;
			}
		} else if (c == '.') {
			in6 = false;
			dots++;
			if (dots > 3) {
				in4 = false;
				break;
			}
		} else {
			in4 = in6 = false;
			break;
		}
	}
	if (dots != 3) {
		in4 = false;
	}
	if (*p == ':') {
		p++;
		int port = 53;
		size_t len = parse_int(p, &port);
		if (len > 0) {
			p += len;
			forwarder.port = port;
		} else {
			in4 = in6 = false;
		}
	}
	p += parse_space(p);
	if (*p) {
		in4 = in6 = false;
	}
	name = std::string(host_begin, host_end - host_begin);

	InetResolver::Addr addr;
	auto type = InetResolver::UNDEFINED;
	if (in4) {
		type = InetResolver::IN4;
	} else if (in6) {
		type = InetResolver::IN6;
	}
	m->resolver.resolve(name.c_str(), type, &addr);
	if (addr.empty()) {
		forwarder = {};
	} else if (type == InetResolver::IN4) {
		struct in_addr const *p = (struct in_addr const *)addr.to_in4(0);
		forwarder.af_type = AF_INET;
		memcpy(forwarder.addr, &p->s_addr, 4);
	} else if (type == InetResolver::IN6) {
		struct in6_addr const *p = (struct in6_addr const *)addr.to_in6(0);
		forwarder.af_type = AF_INET6;
		memcpy(forwarder.addr, &p->s6_addr, 16);
	}

	m->forwarder = forwarder;
}

void Behind::clean()
{
	uint64_t now = misc::get_tick_count();
	size_t i = m->queries.size();
	while (i > 0) {
		i--;
		if (now - m->queries[i].time >= 1000) { // 1 second
			m->queries.erase(m->queries.begin() + i);
		}
	}
}

bool Behind::take_query(uint16_t id, Behind::query_t *out)
{
	bool ok = false;
	size_t i = m->queries.size();
	while (i > 0) {
		i--;
		query_t const &q = m->queries[i];
		if (id == q.upstream_id) {
			if (out) {
				*out = q;
				out = 0;
				ok = true;
			}
			m->queries.erase(m->queries.begin() + i);
		}
	}
	return ok;
}

void Behind::delete_pending_query(uint16_t id)
{
	query_t q;
	take_query(id, &q);
}

void Behind::push_query(const Behind::query_t &query)
{
	take_query(query.upstream_id, 0);
	m->queries.push_back(query);
}

void Behind::init_ttl()
{
	m->ttl = 60;
}

void Behind::parse_dns_packet(const char *begin, const char *end, Behind::dns_header_t *header, std::list<Behind::question_t> *questions, std::list<Behind::answer_t> *answers)
{
	char const *ptr = begin;

	header->id = ntohs(*(uint16_t *)&ptr[0]);
	header->flags = ntohs(*(uint16_t *)&ptr[2]);
	header->qdcount = ntohs(*(uint16_t *)&ptr[4]);
	header->ancount = ntohs(*(uint16_t *)&ptr[6]);
	header->nscount = ntohs(*(uint16_t *)&ptr[8]);
	header->arcount = ntohs(*(uint16_t *)&ptr[10]);
	ptr += 12;

	for (int i = 0; i < header->qdcount; i++) {
		question_t q;
		int n = parse_question_section(begin, end, ptr, &q);
		if (n > 0 && !q.name.empty()) {
			ptr += n;
			questions->push_back(q);
		}
	}

	for (int i = 0; i < header->ancount; i++) {
		answer_t a;
		int n = decode_name(begin, end, ptr, &a.name);
		if (n > 0 && !a.name.empty()) {
			ptr += n;
		}
		if (ptr + 10 <= end) {
			uint16_t tmp[5];
			memcpy(tmp, ptr, 10);
			a.type = (DNS_TYPE)ntohs(tmp[0]);
			a.clas = ntohs(tmp[1]);
			a.ttl = ntohl(*(uint32_t *)&tmp[2]);
			uint16_t rdlen = ntohs(tmp[4]);
			ptr += 10;
			if (ptr + rdlen <= end) {
				std::list<answer_t>::iterator it = answers->insert(answers->end(), answer_t());
				*it = a;
				if (rdlen > 0) {
					it->data.resize(rdlen);
					memcpy(&it->data[0], ptr, rdlen);
					ptr += rdlen;
				}
			}
		}
	}
}

static void init_sa4(struct sockaddr_in *sa4, int port)
{
	memset(sa4, 0, sizeof(*sa4));
	sa4->sin_family = AF_INET;
	sa4->sin_addr.s_addr = INADDR_ANY;
	sa4->sin_port = htons(port);
}

static void init_sa6(struct sockaddr_in6 *sa6, int port)
{
	memset(sa6, 0, sizeof(*sa6));
	sa6->sin6_family = AF_INET6;
	sa6->sin6_addr = IN6ADDR_ANY_INIT;
	sa6->sin6_port = htons(port);
}

bool Behind::is_nxdomain(std::string const &name)
{
	std::string key = misc::strtolower(name);
	auto it = m->option.nxdomain.find(key);
	if (it != m->option.nxdomain.end()) {
		return true;
	}
	return false;
}

void Behind::process(void *private_d, int family, int sock)
{
	Private::D *d = static_cast<Private::D *>(private_d);

	char buf[2000];
	if (family == AF_INET || family == AF_INET6) {
		socklen_t salen = sizeof(d->sa4);
		int len = 0;
		if (family == AF_INET) {
			len = recvfrom(d->sock4, buf, sizeof(buf), 0, (struct sockaddr *)&d->sa4, &salen);
		} else if (family == AF_INET6) {
			len = recvfrom(d->sock6, buf, sizeof(buf), 0, (struct sockaddr *)&d->sa6, &salen);
		}
		if (len < 12 || len > (int)sizeof(buf)) {
			return;
		}

		dns_header_t header;
		std::list<question_t> questions;
		std::list<answer_t> answers;
		parse_dns_packet(buf, buf + len, &header, &questions, &answers);

		if ((header.flags & 0xf800) == 0x0000) { // standard query
			std::vector<char> res;
			for (std::list<question_t>::const_iterator it = questions.begin(); it != questions.end(); it++) {
				bool nxdomain = true;
				question_t const &q = *it;
				if (!q.name.empty()) {
					if (q.clas == DNS_CLASS_IN) {
						if (q.type == DNS_TYPE::A || q.type == DNS_TYPE::AAAA) {
							logprintf(LOG_DEFAULT, "query: %s %s\n", q.name.c_str(), (q.type == DNS_TYPE::A ? "A" : "AAAA"));
							// check nxdomain list
							if (is_nxdomain(q.name)) {
								nxdomain = true;
							} else {
								// search from cache
								dns_cache_t *cache = nullptr;
								if (q.type == DNS_TYPE::A) {
									cache = &m->dns_cache.a;
								} else if (q.type == DNS_TYPE::AAAA) {
									cache = &m->dns_cache.aaaa;
								}
								if (cache) {
									std::vector<dns_record_t> const *records = cache->find(q.name);
									if (records && !records->empty()) {
										dns_record_t const &rec = records->front();
										uint16_t flags = 0x8180;
										write_dns_header(&res, header.id, flags, 1, 1, 0, 0);
										write_dns_question_rr(&res, q.name, q.type, q.clas);
										write_dns_answer_rr(&res, q.name, q.clas, ttl(), rec);
										if (family == AF_INET) {
											sendto(d->sock4, &res[0], (int)res.size(), 0, (struct sockaddr *)&d->sa4, sizeof(sockaddr_in));
										} else if (family == AF_INET6) {
											sendto(d->sock6, &res[0], (int)res.size(), 0, (struct sockaddr *)&d->sa6, sizeof(sockaddr_in6));
										}
										std::string addr_str = rec.to_string();
										logprintf(LOG_DEFAULT, "response from cache: %s %s\n", q.name.c_str(), addr_str.c_str());
										nxdomain = false;
										break;
									}
								}
								// not found, forward to upstream
								Forwarder forwarder = get_forwarder();
								if (forwarder) {
									uint16_t id = m->txid_gen.next();
									delete_pending_query(id);
									std::vector<char> req;
									req.reserve(1500);
									write_dns_header(&req, id, 0x0100, 1, 0, 0, 0);
									std::string query_name = q.name;
									if (m->option.case_randomize) {
										query_name = randomize_case(query_name);
									}
									write_dns_question_rr(&req, query_name, q.type, DNS_CLASS_IN);
									ssize_t len = 0;
									if (forwarder.af_type == AF_INET) {
										struct sockaddr_in to;
										init_sa4(&to, forwarder.port);
										memcpy(&to.sin_addr.s_addr, forwarder.addr, 4);
										len = sendto(d->sock4, &req[0], (int)req.size(), 0, (struct sockaddr *)&to, sizeof(sockaddr_in)); // forward
									} else if (forwarder.af_type == AF_INET6) {
										struct sockaddr_in6 to;
										init_sa6(&to, forwarder.port);
										memcpy(&to.sin6_addr.s6_addr, forwarder.addr, 16);
										len = sendto(d->sock6, &req[0], (int)req.size(), 0, (struct sockaddr *)&to, sizeof(sockaddr_in6)); // forward
									}
									if (len > 0) {
										query_t t;
										t.time = misc::get_tick_count();
										t.requester_id = header.id;
										t.upstream_id = id;
										t.type = q.type;
										t.client_family = family;
										if (family == AF_INET) {
											t.client_sa4 = d->sa4;
										} else if (family == AF_INET6) {
											t.client_sa6 = d->sa6;
										}
										t.request_name = q.name;
										t.forward_name = query_name;
										push_query(t);
									}
									logprintf(LOG_DEFAULT, "forward: %s\n", query_name.c_str());
									nxdomain = false;
									break;
								}
							}
						}
					}
				}
				if (nxdomain) {
					std::vector<char> res;
					res.reserve(1500);
					uint16_t flags = 0x8003; // NXDOMAIN: no such name
					write_dns_header(&res, header.id, flags, (uint16_t)questions.size(), 0, 0, 0);
					for (std::list<question_t>::const_iterator it = questions.begin(); it != questions.end(); it++) {
						question_t const &q = *it;
						write_dns_question_rr(&res, q.name, q.type, q.clas);
					}
					if (family == AF_INET) {
						sendto(d->sock4, &res[0], (int)res.size(), 0, (struct sockaddr *)&d->sa4, sizeof(sockaddr_in));
					} else if (family == AF_INET6) {
						sendto(d->sock6, &res[0], (int)res.size(), 0, (struct sockaddr *)&d->sa6, sizeof(sockaddr_in6));
					}
					logprintf(LOG_DEFAULT, "response: %s = NXDOMAIN\n", q.name.c_str());
				}
			}
		} else if (header.flags & 0x8000) { // response
			uint16_t id = header.id;
			query_t q;
			if (take_query(id, &q)) {
				if (q.type == DNS_TYPE::A || q.type == DNS_TYPE::AAAA) {
					if (questions.size() == 1 && questions.front().name == q.forward_name) {
						// make answer
						std::vector<dns_record_t> records;
						records.reserve(10);
						for (std::list<answer_t>::const_iterator it = answers.begin(); it != answers.end(); it++) {
							answer_t const &a = *it;
							if (a.clas == DNS_CLASS_IN && a.type == q.type) {
								auto size = a.data.size();
								if ((a.type == DNS_TYPE::A && size == 4) || (a.type == DNS_TYPE::AAAA && size == 16)) {
									dns_record_t item;
									item.type = a.type;
									memcpy(item.addr, &a.data[0], size);
									records.push_back(item);
								}
							}
						}
						// update cahce
						{
							Behind::dns_cache_t *cache = nullptr;
							if (q.type == DNS_TYPE::A) {
								cache = &m->dns_cache.a;
							} else if (q.type == DNS_TYPE::AAAA) {
								cache = &m->dns_cache.aaaa;
							}
							if (cache) {
								cache->insert(q.forward_name, records);
							}
						}
						// send answer
						std::vector<char> res;
						res.reserve(1500);
						uint16_t flags = header.flags;
						write_dns_header(&res, q.requester_id, flags, 0, (uint16_t)records.size(), 0, 0);
						for (int i = 0; i < (int)records.size(); i++) {
							write_dns_answer_rr(&res, q.request_name, DNS_CLASS_IN, ttl(), records[i]);
							logprintf(LOG_DEFAULT, "response: %s = %s\n", q.request_name.c_str(), records[i].to_string().c_str());
						}
						if (q.client_family == AF_INET) {
							sendto(d->sock4, &res[0], (int)res.size(), 0, (struct sockaddr *)&q.client_sa4, sizeof(sockaddr_in));
						} else if (q.client_family == AF_INET6) {
							sendto(d->sock6, &res[0], (int)res.size(), 0, (struct sockaddr *)&q.client_sa6, sizeof(sockaddr_in6));
						}
					}
				}
			}
		}
	}
}

void Behind::main()
{
	Private::D d;

	d.sock4 = socket(PF_INET, SOCK_DGRAM, 0);
	if (d.sock4 == INVALID_SOCKET) {
		throw STRERROR("socket: ");
	}

	d.sock6 = socket(PF_INET6, SOCK_DGRAM, 0);
	if (d.sock6 == INVALID_SOCKET) {
		throw STRERROR("socket: ");
	}

	{
		int yes = 1;
		setsockopt(d.sock4, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
		setsockopt(d.sock6, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&yes, sizeof(yes));
	}

	init_sa4(&d.sa4, listen_port());
	if (bind(d.sock4, (struct sockaddr *)&d.sa4, sizeof(d.sa4)) == SOCKET_ERROR) {
		throw STRERROR("bind: ");
	}

	init_sa6(&d.sa6, listen_port());
	if (bind(d.sock6, (struct sockaddr *)&d.sa6, sizeof(d.sa6)) == SOCKET_ERROR) {
		throw STRERROR("bind: ");
	}

	fd_set fds, readfds;
	FD_ZERO(&readfds);
	FD_SET(d.sock4, &readfds);
	FD_SET(d.sock6, &readfds);
	int maxfd = std::max(d.sock4, d.sock6);

	while (1) {
		memcpy(&fds, &readfds, sizeof(fd_set));
		select(maxfd + 1, &fds, NULL, NULL, NULL);

		if (FD_ISSET(d.sock4, &fds)) {
			process(&d, AF_INET, d.sock4);
		}
		if (FD_ISSET(d.sock6, &fds)) {
			process(&d, AF_INET6, d.sock6);
		}

		clean();
	}

	closesocket(d.sock4);
}

