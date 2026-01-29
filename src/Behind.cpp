#include "Behind.h"
#include "Logger.h"
#include "TransactionIdGenerator.h"
#include "misc.h"
#include "rwfile.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <regex>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <optional>

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

std::string addr_to_string(int family, struct sockaddr *addr)
{
	char buf[INET6_ADDRSTRLEN];
	if (family == AF_INET) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)addr;
		if (inet_ntop(AF_INET, &sa4->sin_addr, buf, sizeof(buf))) {
			return buf;
		}
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)addr;
		if (inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf))) {
			return buf;
		}
	}
	return {};
}

namespace dns {

struct Header {
	uint16_t id;
	uint16_t flags = 0x8180;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

struct Query {
	// int forward_fd;
	uint64_t timestamp;
	uint32_t local_transaction_id;
	uint16_t upstream_id;
	uint16_t requester_id;
	DNS_TYPE type = DNS_TYPE::A;
	// sa_family_t client_family = AF_INET;
	ProtocolFamilyType proto;
	union {
		sockaddr_in client_sa4;
		sockaddr_in6 client_sa6;
	};
	std::string request_name;
	std::string forward_name;
};

struct Question {
	std::string name;
	DNS_TYPE type;
	uint16_t clas;
};
static inline bool operator == (const Question &l, const Question &r)
{
	if (l.name != r.name) return false;
	if (l.type != r.type) return false;
	if (l.clas != r.clas) return false;
	return true;
}

struct CNAME {
	std::string cname;
};

struct NS {
	std::string nsname;
};

struct MX {
	uint16_t preference;
	std::string exchange;
};

struct SOA {
	std::string nname; // name server
	std::string rname; // responsible mail addr
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
};

struct Record {
	std::string name;
	DNS_TYPE type = DNS_TYPE::A;
	uint16_t clas = AF_INET;
	uint32_t ttl = 300;
	uint64_t expire = 0;
	std::vector<uint8_t> bin;
	std::shared_ptr<void> sp;

	// soa

	void set_soa(std::shared_ptr<SOA> soa)
	{
		sp = soa;
	}
	SOA *soa()
	{
		if (type == DNS_TYPE::SOA && sp) {
			return std::static_pointer_cast<SOA>(sp).get();
		}
		return nullptr;
	}
	SOA const *soa() const
	{
		return const_cast<Record *>(this)->soa();
	}

	// cname

	void set_cname(std::shared_ptr<CNAME> cname)
	{
		sp = cname;
	}
	CNAME *cname()
	{
		if (type == DNS_TYPE::CNAME && sp) {
			return std::static_pointer_cast<CNAME>(sp).get();
		}
		return nullptr;
	}
	CNAME const *cname() const
	{
		return const_cast<Record *>(this)->cname();
	}

	// ns

	void set_ns(std::shared_ptr<NS> ns)
	{
		sp = ns;
	}
	NS *ns()
	{
		if (type == DNS_TYPE::NS && sp) {
			return std::static_pointer_cast<NS>(sp).get();
		}
		return nullptr;
	}
	NS const *ns() const
	{
		return const_cast<Record *>(this)->ns();
	}

	// mx

	void set_mx(std::shared_ptr<MX> mx)
	{
		sp = mx;
	}
	MX *mx()
	{
		if (type == DNS_TYPE::MX && sp) {
			return std::static_pointer_cast<MX>(sp).get();
		}
		return nullptr;
	}
	MX const *mx() const
	{
		return const_cast<Record *>(this)->mx();
	}

	//

	std::string to_string() const
	{
		if (type == DNS_TYPE::A && bin.size() == 4) {
			struct sockaddr_in a = {};
			a.sin_addr.s_addr = *(uint32_t *)bin.data();
			return addr_to_string(AF_INET, (struct sockaddr *)&a);
		} else if (type == DNS_TYPE::AAAA && bin.size() == 16) {
			struct sockaddr_in6 a = {};
			memcpy(&a.sin6_addr.s6_addr, bin.data(), 16);
			return addr_to_string(AF_INET6, (struct sockaddr *)&a);
		} else if (type == DNS_TYPE::CNAME && cname()) {
			CNAME const *p = cname();
			if (p) {
				return p->cname;
			}
		}
		return {};
	}
};

static inline bool operator == (const Record &l, const Record &r)
{
	if (l.type != r.type) return false;
	if (l.clas != r.clas) return false;
	if (l.bin.size() != r.bin.size()) return false;
	if (memcmp(l.bin.data(), r.bin.data(), l.bin.size()) != 0) return false;
	return true;
}

struct Message {
	Header header;
	std::vector<Question> questions;
	std::vector<Record> answers;
	std::vector<Record> authorities;
};

class Cache {
public:
	struct Item {
		std::string key;
		uint64_t timestamp = 0;
		uint64_t expire = 0;
		std::vector<Record> answers;
		std::vector<Record> authorities;
	};
private:
	std::vector<Item> items_;
	std::unordered_map<std::string, size_t> index_;
	std::string make_key(std::string const &name) const
	{
		return misc::strtolower(name);
	}
public:
	struct Entry {
		std::vector<Record> answers;
		std::vector<Record> authorities;
	};
	std::optional<Entry> find(std::string const &name)
	{
		auto key = make_key(name);
		auto it = index_.find(key);
		if (it != index_.end()) {
			auto now = misc::get_tick_count();
			auto expire = items_[it->second].expire;
			if (now < expire) {
				Entry ret;
				ret.answers = items_[it->second].answers;
				ret.authorities = items_[it->second].authorities;
				for (size_t i = 0; i < ret.answers.size(); i++) {
					auto exp = ret.answers[i].expire;
					if (now < exp) {
						ret.answers[i].ttl = (uint32_t)((exp - now) / 1000);
					} else {
						ret.answers[i].ttl = 0;
					}
				}
				return ret;
			}
		}
		return std::nullopt;
	}
	void insert(std::string const &name, Message const &msg)
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
					if (now < items_[n - 1].expire) {
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
		item->expire = now + 600 * 1000;
		item->answers = msg.answers;
		item->authorities = msg.authorities;
		for (size_t i = 0; i < item->answers.size(); i++) {
			item->answers[i].expire = now + item->answers[i].ttl * 1000;
			item->expire = std::min(item->expire, item->answers[i].expire);
		}
	}
};

} // namespace dns

struct Behind::Private {
	Option option;
	Hosts hosts;
	uint32_t local_transaction_id = 0;
	TransactionIdGenerator txid_gen;
	InetResolver resolver;

	Behind::SocketMode socket_mode;
	int epoll_fd = -1;
	std::vector<epoll_event> epoll_events{10};

	int ttl = 5 * 60;
	struct {
		dns::Cache a;
		dns::Cache aaaa;
		dns::Cache soa;
	} dns_cache;
	std::vector<dns::Query> queries;
	std::vector<Forwarder> forwarder;
};

struct Behind::InternalData {
	struct In {
		int dgram_fd = -1;
		int listen_fd = -1;
		int stream_fd = -1;
		int family = -1;
		union {
			struct sockaddr_in sa4;
			struct sockaddr_in6 sa6;
		};
		struct epoll_event ev;
	};
	In in4_udp, in6_udp;
	In in4_tcp, in6_tcp; // wip: experimental: tcp support
};

const InetResolver::Addr *Hosts::find(const std::string &name)
{
	std::string key = misc::strtolower(name);
	auto it = map_.find(key);
	if (it != map_.end()) {
		return &it->second;
	}
	return nullptr;
}

InetResolver::Addr &Hosts::operator [](const std::string &name)
{
	return map_[misc::strtolower(name)];
}

Behind::Behind(const Option &opt)
	: m(new Private())
{
	m->option = opt;

	init_forwarder();
}

Behind::~Behind()
{
	delete m;
}

bool Behind::eqi(const std::string &l, const std::string &r)
{
	return stricmp(l.c_str(), r.c_str()) == 0;
}

uint16_t Behind::listen_port() const
{
	return m->option.listen_port;
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

void Behind::write_us(void *out, uint16_t v)
{
	v = htons(v);
	memcpy(out, (char const *)&v, 2);
}

void Behind::write_ul(void *out, uint32_t v)
{
	v = htonl(v);
	memcpy(out, (char const *)&v, 4);
}

bool Behind::write_name(std::vector<char> *out, std::map<std::string, size_t> *namemap, const std::string &name)
{
	char const *name_begin = name.c_str();
	char const *name_end = name_begin + name.size();
	char const *srcptr = name_begin;
	while (srcptr < name_end) {
		if (namemap) {
			auto it = namemap->find(srcptr);
			if (it != namemap->end()) {
				uint16_t offset = it->second;
				offset |= 0xc000;
				write_us(out, offset);
				return true;
			}
		}
		char const *dot = strchr(srcptr, '.');
		int len = (dot ? dot : name_end) - srcptr;
		if (len < 1 || len > 63) return false;
		if (namemap) {
			(*namemap)[srcptr] = out->size();
		}
		write(out, (char)len);
		write(out, srcptr, len);
		if (!dot) {
			break;
		}
		srcptr += len + 1;
	}
	write(out, (char)0);
	return true;
}

int Behind::decode_name(const char *begin, const char *end, const char *ptr, std::vector<char> *out)
{
	if (begin && ptr && begin <= ptr && ptr < end) {
		char const *start = ptr;
		while (ptr < end) {
			if ((*ptr & 0xc0) == 0xc0) {
				if (ptr + 1 < end) {
					int o = ((ptr[0] & 0x3f) << 8) | (ptr[1] & 0xff);
					decode_name(begin, end, begin + o, out);
					ptr += 2;
				}
				break;
			}
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

void Behind::write_dns_question_rr(std::vector<char> *out, std::map<std::string, size_t> *namemap, const std::string &name, DNS_TYPE type, uint16_t clas)
{
	write_name(out, namemap, name);
	write_us(out, (uint16_t)type);
	write_us(out, clas);
}

std::shared_ptr<dns::SOA> fake_soa()
{
	std::shared_ptr<dns::SOA> soa = std::make_shared<dns::SOA>();
	soa->nname = "ns.example.invalid";
	soa->rname = "admin.example.invalid";
	soa->serial = 1;
	soa->refresh = 3600;
	soa->retry = 600;
	soa->expire = 1800;
	soa->minimum = 60;
	return soa;
}

bool Behind::write_dns_answer_rr(std::vector<char> *out, std::map<std::string, size_t> *namemap, std::string const &name, uint16_t clas, uint32_t ttl, const dns::Record &item)
{
	write_name(out, namemap, name);
	write_us(out, (int)item.type);
	write_us(out, clas);
	write_ul(out, ttl);

	if (item.type == DNS_TYPE::CNAME) {
		dns::CNAME const *cname = item.cname();
		if (!cname) return false;
		size_t i = out->size();
		write_us(out, 0);
		write_name(out, namemap, cname->cname);
		write_us(&out->at(i), out->size() - i - 2);
	} else if (item.type == DNS_TYPE::NS) {
		dns::NS const *ns = item.ns();
		if (!ns) return false;
		size_t i = out->size();
		write_us(out, 0);
		write_name(out, namemap, ns->nsname);
		write_us(&out->at(i), out->size() - i - 2);
	} else if (item.type == DNS_TYPE::MX) {
		dns::MX const *mx = item.mx();
		if (!mx) return false;
		size_t i = out->size();
		write_us(out, 0);
		write_us(out, mx->preference);
		write_name(out, namemap, mx->exchange);
		write_us(&out->at(i), out->size() - i - 2);
	} else if (item.type == DNS_TYPE::SOA) {
		auto WriteSOA = [&](dns::SOA const &soa){
			size_t i = out->size();
			write_us(out, 0);
			write_name(out, namemap, soa.nname);
			write_name(out, namemap, soa.rname);
			write_ul(out, soa.serial);
			write_ul(out, soa.refresh);
			write_ul(out, soa.retry);
			write_ul(out, soa.expire);
			write_ul(out, soa.minimum);
			write_us(&out->at(i), out->size() - i - 2);
		};
		if (item.soa()) {
			WriteSOA(*item.soa());
		}
	} else {
		int len = item.bin.size();
		if (item.type == DNS_TYPE::A && len == 4) {
			// len = 4;
		} else if (item.type == DNS_TYPE::AAAA && len == 16) {
			// len = 16;
		} else {
			return false;
		}
		write_us(out, len);
		write(out, (char const *)item.bin.data(), len);
	}
	return true;
}

int Behind::parse_question_section(const char *begin, const char *end, const char *ptr, dns::Question *out)
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

std::vector<Forwarder> Behind::get_forwarder()
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

InetResolver::Type parse_inet_address(std::string name, InetResolver::Addr *addr_out, int *port_out)
{
	char const *host_begin = name.c_str();
	char const *host_end = host_begin + name.size();

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
		int port = STANDARD_DNS_PORT;
		size_t len = misc::parse_int(p, &port);
		if (len > 0) {
			p += len;
			if (port_out) {
				*port_out = port;
			}
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
	if (in4) {
		addr.type = InetResolver::IN4;
		struct sockaddr_in sa4 = {};
		inet_pton(AF_INET, name.c_str(), &sa4.sin_addr);
		addr.add_in4(&sa4.sin_addr.s_addr);
	} else if (in6) {
		addr.type = InetResolver::IN6;
		struct sockaddr_in6 sa6 = {};
		inet_pton(AF_INET6, name.c_str(), &sa6.sin6_addr);
		addr.add_in6(&sa6.sin6_addr.s6_addr);
	}

	if (addr_out) {
		*addr_out = addr;
	}

	return addr.type;
}

void Behind::init_forwarder()
{
	for (std::string const &name : m->option.forward_addr) {
		InetResolver::Addr addr;
		int port = STANDARD_DNS_PORT;

		InetResolver::Type type = parse_inet_address(name, &addr, &port);

		m->resolver.resolve(name.c_str(), type, &addr);

		Forwarder forwarder;
		forwarder.port = port;
		if (!addr.empty()) {
			if (type == InetResolver::IN4) {
				struct in_addr const *p = (struct in_addr const *)addr.to_in4(0);
				forwarder.af_type = AF_INET;
				memcpy(forwarder.addr, &p->s_addr, 4);
			} else if (type == InetResolver::IN6) {
				struct in6_addr const *p = (struct in6_addr const *)addr.to_in6(0);
				forwarder.af_type = AF_INET6;
				memcpy(forwarder.addr, &p->s6_addr, 16);
			}
		}

		m->forwarder.push_back(forwarder);
	}
}

void Behind::clean()
{
	uint64_t now = misc::get_tick_count();
	size_t i = m->queries.size();
	while (i > 0) {
		i--;
		if (now - m->queries[i].timestamp >= 1000) { // 1 second
			m->queries.erase(m->queries.begin() + i);
		}
	}
}

void Behind::clean_transaction(uint32_t id)
{
	size_t i = m->queries.size();
	while (i > 0) {
		i--;
		if (id == m->queries[i].local_transaction_id) {
			m->queries.erase(m->queries.begin() + i);
		}
	}
}

bool Behind::take_query(uint16_t id, dns::Query *out)
{
	for (dns::Query const &q : m->queries) {
		if (id == q.upstream_id) {
			*out = q;
			clean_transaction(q.local_transaction_id);
			return true;
		}
	}
	return false;
}

void Behind::push_query(const dns::Query &query)
{
	take_query(query.upstream_id, 0);
	m->queries.push_back(query);
}

void Behind::parse_dns_message(const char *begin, const char *end, dns::Message *msg)
{
	*msg = {};

	char const *ptr = begin;

	uint16_t tmp[6];
	memcpy(tmp, ptr, 12);
	ptr += 12;
	msg->header.id = ntohs(tmp[0]);
	msg->header.flags = ntohs(tmp[1]);
	msg->header.qdcount = ntohs(tmp[2]);
	msg->header.ancount = ntohs(tmp[3]);
	msg->header.nscount = ntohs(tmp[4]);
	msg->header.arcount = ntohs(tmp[5]);

	for (int i = 0; i < msg->header.qdcount; i++) {
		dns::Question q;
		int n = parse_question_section(begin, end, ptr, &q);
		if (n > 0 && !q.name.empty()) {
			ptr += n;
			msg->questions.push_back(q);
		}
	}

	auto ParseRecord = [&](int count, std::vector<dns::Record> *answers){
		for (int i = 0; i < count; i++) {
			dns::Record a;
			int n = decode_name(begin, end, ptr, &a.name);
			if (n > 0 && !a.name.empty()) {
				ptr += n;
			}
			if (ptr + 10 <= end) {
				uint16_t tmp[5];
				memcpy(tmp, ptr, 10);
				a.type = (DNS_TYPE)ntohs(tmp[0]);
				a.clas = ntohs(tmp[1]);
				memcpy(&a.ttl, tmp + 2, 4); // a.ttl = ntohl(*(uint32_t *)&tmp[2]); // -Wstrict-aliasing
				a.ttl = ntohl(a.ttl);
				uint16_t rdlen = ntohs(tmp[4]);
				ptr += 10;
				if (ptr + rdlen <= end) {
					auto it = answers->insert(answers->end(), dns::Record());
					*it = a;
					if ((a.type == DNS_TYPE::A && rdlen == 4) || (a.type == DNS_TYPE::AAAA && rdlen == 16)) {
						if (rdlen > 0) {
							it->bin.resize(rdlen);
							memcpy(it->bin.data(), ptr, rdlen);
							ptr += rdlen;
						}
					} else if (a.type == DNS_TYPE::CNAME && rdlen < 256) {
						if (rdlen > 0) {
							std::shared_ptr<dns::CNAME> cname = std::make_shared<dns::CNAME>();
							int n = decode_name(begin, end, ptr, &cname->cname);
							if (n > 0 && !cname->cname.empty()) {
								cname->cname = misc::strtolower(cname->cname);
								it->set_cname(cname);
							}
							ptr += rdlen;
						}
					} else if (a.type == DNS_TYPE::NS && rdlen < 256) {
						if (rdlen > 0) {
							std::shared_ptr<dns::NS> ns = std::make_shared<dns::NS>();
							int n = decode_name(begin, end, ptr, &ns->nsname);
							if (n > 0 && !ns->nsname.empty()) {
								ns->nsname = misc::strtolower(ns->nsname);
								it->set_ns(ns);
							}
							ptr += rdlen;
						}
					} else if (a.type == DNS_TYPE::MX) {
						if (rdlen > 0) {
							std::shared_ptr<dns::MX> mx = std::make_shared<dns::MX>();
							if (rdlen >= 2) {
								mx->preference = ntohs(*(uint16_t *)ptr);
								ptr += 2;
							}
							int n = decode_name(begin, end, ptr, &mx->exchange);
							if (n > 0 && !mx->exchange.empty()) {
								mx->exchange = misc::strtolower(mx->exchange);
								it->set_mx(mx);
							}
							ptr += rdlen;
						}
					} else if (a.type == DNS_TYPE::SOA) {
						std::shared_ptr<dns::SOA> soa = std::make_shared<dns::SOA>();
						if (rdlen > 0) {
							int n = decode_name(begin, end, ptr, &soa->nname);
							if (n > 0 && !soa->nname.empty()) {
								ptr += n;
							}
						}
						if (rdlen > 0) {
							int n = decode_name(begin, end, ptr, &soa->rname);
							if (n > 0 && !soa->rname.empty()) {
								ptr += n;
							}
						}
						if (ptr + 20 <= end) {
							uint32_t tmp[5];
							memcpy(tmp, ptr, 20);
							ptr += 20;
							soa->serial = ntohl(tmp[0]);
							soa->refresh = ntohl(tmp[1]);
							soa->retry = ntohl(tmp[2]);
							soa->expire = ntohl(tmp[3]);
							soa->minimum = ntohl(tmp[4]);
							soa->nname = misc::strtolower(soa->nname);
							soa->rname = misc::strtolower(soa->rname);
							it->set_soa(soa);
						}
					}
				}
			}
		}
	};
	ParseRecord(msg->header.ancount, &msg->answers);
	ParseRecord(msg->header.nscount, &msg->authorities);
}

static void init_sa4(struct sockaddr_in *sa4, in_addr const *addr, int port)
{
	memset(sa4, 0, sizeof(*sa4));
	sa4->sin_family = AF_INET;
	if (addr) {
		memcpy(&sa4->sin_addr, addr, 4);
	} else {
		sa4->sin_addr.s_addr = INADDR_ANY;
	}
	sa4->sin_port = htons(port);
}

static void init_sa6(struct sockaddr_in6 *sa6, in6_addr const *addr, int port)
{
	memset(sa6, 0, sizeof(*sa6));
	sa6->sin6_family = AF_INET6;
	if (addr) {
		memcpy(&sa6->sin6_addr, addr, 16);
	} else {
		sa6->sin6_addr = IN6ADDR_ANY_INIT;
	}
	sa6->sin6_port = htons(port);
}

struct SendTo {
	int sock = -1;
	int family = AF_UNSPEC;
	int socktype = SOCK_DGRAM;
	union {
		sockaddr_in sa4;
		sockaddr_in6 sa6;
	} to;
	SendTo(int family, int socktype)
		: family(family)
		, socktype(socktype)
	{

	}
	void set_sa4(struct sockaddr_in const *sa)
	{
		family = AF_INET;
		if (sa) {
			memcpy(&to.sa4, sa, sizeof(sockaddr_in));
		} else {
			memset(&to.sa4, 0, sizeof(sockaddr_in));
		}
	}
	void set_sa6(struct sockaddr_in6 const *sa)
	{
		family = AF_INET6;
		if (sa) {
			memcpy(&to.sa6, sa, sizeof(sockaddr_in6));
		} else {
			memset(&to.sa6, 0, sizeof(sockaddr_in6));
		}
	}
	void set_sa4(int sock, struct sockaddr_in const *sa)
	{
		this->sock = sock;
		set_sa4(sa);
	}
	void set_sa6(int sock, struct sockaddr_in6 const *sa)
	{
		this->sock = sock;
		set_sa6(sa);
	}
	void set_sa4(in_addr const *addr, int port)
	{
		sockaddr_in sa;
		init_sa4(&sa, addr, port);
		set_sa4(&sa);
	}
	void set_sa6(in6_addr const *addr, int port)
	{
		sockaddr_in6 sa;
		init_sa6(&sa, addr, port);
		set_sa6(&sa);
	}
	void set_sa4(int sock, in_addr const *addr, int port)
	{
		this->sock = sock;
		set_sa4(addr, port);
	}
	void set_sa6(int sock, in6_addr const *addr, int port)
	{
		this->sock = sock;
		set_sa6(addr, port);
	}
	std::string addr_to_string() const
	{
		if (family == AF_INET) {
			return ::addr_to_string(family, (struct sockaddr *)&to.sa4);
		}
		if (family == AF_INET6) {
			return ::addr_to_string(family, (struct sockaddr *)&to.sa6);
		}
		return {};
	}
	ssize_t send(void const *buf, size_t len)
	{
		int flags = 0;
		if (socktype == SOCK_DGRAM) {
			if (family == AF_INET) {
				return ::sendto(sock, buf, len, flags, (struct sockaddr *)&to.sa4, sizeof(sockaddr_in));
			}
			if (family == AF_INET6) {
				return ::sendto(sock, buf, len, flags, (struct sockaddr *)&to.sa6, sizeof(sockaddr_in6));
			}
		} else if (socktype == SOCK_STREAM) {
			if (family == AF_INET) {
				return ::send(sock, buf, len, flags);
			}
			if (family == AF_INET6) {
				return ::send(sock, buf, len, flags);
			}
		}
		return -1;
	}
};

bool Behind::is_nxdomain(std::string const &name) const
{
	return m->option.domain_filter.find(name) == DomainFilter::NXDOMAIN;
}

bool Behind::is_nodata_aaaa(std::string const &name) const
{
	return m->option.domain_filter.find(name) == DomainFilter::NODATA_AAAA;
}

char const *dns_type_to_string(DNS_TYPE type)
{
	switch (type) {
	case DNS_TYPE::A:
		return "A";
	case DNS_TYPE::NS:
		return "NS";
	case DNS_TYPE::CNAME:
		return "CNAME";
	case DNS_TYPE::SOA:
		return "SOA";
	case DNS_TYPE::PTR:
		return "PTR";
	case DNS_TYPE::AAAA:
		return "AAAA";
	default:
		return "?";
	}
}

struct Behind::Packet {
	dns::Question q;
	std::vector<char> buffer;
	operator bool () const
	{
		return !buffer.empty();
	}
};

Behind::Packet Behind::make_dns_message(dns::Message const &msg, bool tcp)
{
	Packet ret;
	std::map<std::string, size_t> namemap;

	auto LimitCount = [](size_t n){
		return uint16_t(std::min(n, (size_t)100));
	};

	dns::Header h = msg.header;
	h.qdcount = LimitCount(msg.answers.size());
	h.ancount = LimitCount(msg.answers.size());
	h.nscount = LimitCount(msg.authorities.size());
	h.arcount = 0;

	write_dns_header(&ret.buffer, h.id, h.flags, 1, h.ancount, h.nscount, 0);

	for (auto it = msg.questions.begin(); it != msg.questions.end(); it++) {
		dns::Question const &q = *it;
		write_dns_question_rr(&ret.buffer, &namemap, q.name, q.type, q.clas);
	}

	if (!msg.questions.empty()) {
		ret.q = msg.questions.front();
	}

	for (int i = 0; i < h.ancount; i++) {
		dns::Record const &r = msg.answers[i];
		std::string name = stricmp(ret.q.name.c_str(), r.name.c_str()) == 0 ? ret.q.name : misc::strtolower(r.name);
		if (!write_dns_answer_rr(&ret.buffer, &namemap, name, ret.q.clas, r.ttl, r)) {
			return {};
		}
	}

	for (int i = 0; i < h.nscount; i++) {
		dns::Record const &r = msg.authorities[i];
		std::string name = stricmp(ret.q.name.c_str(), r.name.c_str()) == 0 ? ret.q.name : misc::strtolower(r.name);
		if (!write_dns_answer_rr(&ret.buffer, &namemap, name, ret.q.clas, r.ttl, r)) {
			return {};
		}
	}

	if (tcp) {
		uint16_t len = htons((uint16_t)ret.buffer.size());
		ret.buffer.insert(ret.buffer.begin(), (char const *)&len, (char const *)&len + 2);
	}

	return ret;
}

bool Behind::send_dns_message(InternalData *d, ProtocolFamilyType const &proto, dns::Message const &msg, bool forward, bool from_cache)
{
	bool tcp = proto.type() == SOCK_STREAM;
	Packet packet = make_dns_message(msg, tcp);
	if (!packet) return false;

	bool ok = false;
	std::string client;
	SendTo sender(proto.family(), proto.type());
	if (proto.type() == SOCK_DGRAM) {
		if (proto.family() == AF_INET) {
			sender.set_sa4(d->in4_udp.dgram_fd, &d->in4_udp.sa4);
		} else if (proto.family() == AF_INET6) {
			sender.set_sa6(d->in6_udp.dgram_fd, &d->in6_udp.sa6);
		}
		ok = sender.send(&packet.buffer[0], packet.buffer.size()) == (ssize_t)packet.buffer.size();
	} else if (proto.type() == SOCK_STREAM) {
		if (proto.family() == AF_INET) {
			sender.set_sa4(d->in4_tcp.stream_fd, nullptr);
		} else if (proto.family() == AF_INET6) {
			sender.set_sa6(d->in6_tcp.stream_fd, nullptr);
		}
		ssize_t len = sender.send(&packet.buffer[0], packet.buffer.size());
		logprintf(LOG_DEFAULT, "---%d\n", (int)len);
		// ok = sender.send(&packet.buffer[0], packet.buffer.size()) == (ssize_t)packet.buffer.size();
	}
	client = sender.addr_to_string();

	char const *comment = "";
	if (from_cache) {
		comment = " (from cache)";
	}

	char const *qtype = dns_type_to_string(packet.q.type);
	if (forward) {
		logprintf(LOG_DEFAULT, "F: %s\n", packet.q.name.c_str());
	} else if ((msg.header.flags & 0x000f) == 3) { // NXDOMAIN
		logprintf(LOG_DEFAULT, "R: <<%s %s NXDOMAIN>> to %s\n"
				  , packet.q.name.c_str()
				  , qtype
				  , client.c_str()
				  );
	} else if (msg.answers.size() > 0) {
		for (size_t i = 0; i < msg.answers.size(); i++) {
			dns::Record const &r = msg.answers[i];
			std::string name = misc::strtolower(packet.q.name);
			std::string addr_str = r.to_string();
			logprintf(LOG_DEFAULT, "R: <<%s %s %s>> to %s%s\n"
					  , name.c_str()
					  , qtype
					  , addr_str.c_str()
					  , client.c_str()
					  , comment
					  );
		}
	} else {
		logprintf(LOG_DEFAULT, "R: <<%s %s NOANSWER>> to %s%s\n"
				  , packet.q.name.c_str()
				  , qtype
				  , client.c_str()
				  , comment
				  );
	}

	if (0) {
		if (msg.header.flags & 0x8000) {
			if (stricmp(packet.q.name.c_str(), "www.google.com") == 0) {
				char const *path = "testcase/google_packet.bin";
				writefile(path, &packet.buffer);
			} else if (stricmp(packet.q.name.c_str(), "doubleclick.net") == 0) {
				char const *path = "testcase/doubleclick_packet.bin";
				writefile(path, &packet.buffer);
			} else if (stricmp(packet.q.name.c_str(), "www.soramimi.jp") == 0) {
				char const *path = "testcase/soramimi_packet.bin";
				writefile(path, &packet.buffer);
			} else if (stricmp(packet.q.name.c_str(), "www.amazon.co.jp") == 0) {
				char const *path = "testcase/amazon_packet.bin";
				writefile(path, &packet.buffer);
			}
		} else {
			if (stricmp(packet.q.name.c_str(), "www.google.com") == 0) {
				char const *path = "testcase/google_query.bin";
				writefile(path, &packet.buffer);
			} else if (stricmp(packet.q.name.c_str(), "doubleclick.net") == 0) {
				char const *path = "testcase/doubleclick_query.bin";
				writefile(path, &packet.buffer);
			} else if (stricmp(packet.q.name.c_str(), "www.soramimi.jp") == 0) {
				char const *path = "testcase/soramimi_query.bin";
				writefile(path, &packet.buffer);
			} else if (stricmp(packet.q.name.c_str(), "www.amazon.co.jp") == 0) {
				char const *path = "testcase/amazon_query.bin";
				writefile(path, &packet.buffer);
			}
		}
	}

	return ok;
}

InetResolver::Addr const *Behind::find_host(std::string const &name) const
{
	return m->hosts.find(name);
}

uint32_t Behind::next_local_transaction_id()
{
	return m->local_transaction_id++;
}

bool Behind::accept_dns_type(DNS_TYPE t)
{
	switch (t) {
	case DNS_TYPE::A:
	case DNS_TYPE::NS:
	case DNS_TYPE::AAAA:
	case DNS_TYPE::CNAME:
	case DNS_TYPE::SOA:
	case DNS_TYPE::MX:
		return true;
	}
	return false;
}

bool Behind::_experimental_forward_tcp(std::vector<dns::Question> const &questions, dns::Message *msg_out)
{
	InetResolver::Addr addr;
	InetResolver resolver;
	resolver.resolve("192.168.1.1", InetResolver::IN4, &addr);
	void const *a = addr.to_in4(0);
	sockaddr_in sa = {};
	sa.sin_family = AF_INET;
	memcpy(&sa.sin_addr.s_addr, a, 4);
	sa.sin_port = htons(53);

	int sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		logprintf(LOG_DEFAULT, "socket: %s\n", strerror(errno));
		return false;
	}

	bool ok = false;
	if (connect(sock, (sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
		logprintf(LOG_DEFAULT, "connect: %s\n", strerror(errno));
	} else {
		dns::Message msg = {};
		msg.header.id = 1;
		msg.header.flags = 0x0100;
		// msg.questions.push_back({});
		// msg.questions.back().name = "www.google.com";
		// msg.questions.back().type = DNS_TYPE::A;
		// msg.questions.back().clas = DNS_CLASS_IN;
		msg.questions = questions;
		Packet packet = make_dns_message(msg, false);
		uint16_t len = htons((uint16_t)packet.buffer.size());
		send(sock, (char *)&len, 2, 0);
		send(sock, packet.buffer.data(), packet.buffer.size(), 0);
		char tmp[4096];
		int n = recv(sock, tmp, sizeof(tmp), 0);
		parse_dns_message(tmp + 2, tmp + n, msg_out);
		ok = true;
	}

	closesocket(sock);
	return ok;
}

std::vector<char> Behind::read(InternalData *d, ProtocolFamilyType const &proto)
{
	std::vector<char> buf;
	int len = 0;
	if (proto.type() == SOCK_DGRAM) {
		int sock = INVALID_SOCKET;
		struct sockaddr *sa = nullptr;
		socklen_t salen = 0;
		if (proto.family() == AF_INET) {
			sock = d->in4_udp.dgram_fd;
			sa = (struct sockaddr *)&d->in4_udp.sa4;
			salen = sizeof(sockaddr_in);
		} else if (proto.family() == AF_INET6) {
			sock = d->in6_udp.dgram_fd;
			sa = (struct sockaddr *)&d->in6_udp.sa6;
			salen = sizeof(sockaddr_in6);
		} else {
			return {};
		}
		buf.resize(1500);
		len = recvfrom(sock, buf.data(), buf.size(), 0, sa, &salen);
		if (len > 0) {
			buf.resize(len);
			return buf;
		}
	} else if (proto.type() == SOCK_STREAM) {
		int sock = INVALID_SOCKET;
		if (proto.family() == AF_INET) {
			sock = d->in4_tcp.stream_fd;
		} else if (proto.family() == AF_INET6) {
			sock = d->in6_tcp.stream_fd;
		} else {
			return {};
		}
		uint16_t len;
		if (::read(sock, &len, 2) == 2) {
			len = ntohs(len);
			if (len > 0) {
				buf.resize(len);
				if (::read(sock, buf.data(), buf.size()) == len) {
					return buf;
				}
			}
		}
	}
	return {};
}


void Behind::process(InternalData *d, ProtocolFamilyType const &proto)
{
	if (proto.family() == AF_INET || proto.family() == AF_INET6) {
		std::vector<char> buf = read(d, proto);
		if (buf.size() < 12) return;

		dns::Message received;
		parse_dns_message(buf.data(), buf.data() + buf.size(), &received);

		auto Cache = [&](DNS_TYPE type)-> dns::Cache * {
			switch (type) {
			case DNS_TYPE::A:    return &m->dns_cache.a;
			case DNS_TYPE::AAAA: return &m->dns_cache.aaaa;
			case DNS_TYPE::SOA:  return &m->dns_cache.soa;
			}
			return nullptr;
		};

		if ((received.header.flags & 0xf800) == 0x0000) { // standard query

			{ // experimental
				if (proto.type() == SOCK_STREAM) {
					if (proto.family() == AF_INET) {
						dns::Message msg;
						if (_experimental_forward_tcp(received.questions, &msg)) {
							msg.header.id = received.header.id;
							// send
							InternalData d2 = *d;
							send_dns_message(&d2, proto, msg, false, false);
						}
						return;
					}
				}
			}

			for (auto it = received.questions.begin(); it != received.questions.end(); it++) {
				dns::Question const &q = *it;

				enum class State {
					NONE,
					FORWARD,
					NXDOMAIN,
					NODATA,
				};
				State state = State::NONE;
				if (!q.name.empty()) {
					if (q.clas == DNS_CLASS_IN) {
						if (accept_dns_type(q.type)) {
							logprintf(LOG_DEFAULT, "Q: %s %s\n", q.name.c_str(), dns_type_to_string(q.type));
							state = State::FORWARD;
							{
								// check known hosts
								InetResolver::Addr const *addr = m->hosts.find(q.name);
								if (addr) {
									state = State::NONE;
									std::vector<dns::Record> rec;
									if ((q.type == DNS_TYPE::A && addr->type == InetResolver::IN4) || (q.type == DNS_TYPE::AAAA && addr->type == InetResolver::IN6)) {
										dns::Record r;
										r.name = q.name;
										r.type = q.type;
										r.ttl = ttl();
										for (std::vector<uint8_t> const &a : addr->addr) {
											r.bin = a;
											rec.push_back(r);
										}
										dns::Message sending;
										sending.header = received.header;
										sending.header.flags = 0x8180;
										sending.questions = {q};
										sending.answers = rec;
										send_dns_message(d, proto, sending, false, false);
									} else {
										state = State::NXDOMAIN;
									}
								}
							}
							if (state == State::NXDOMAIN) {
								// nop
							} else if (is_nxdomain(q.name)) {
								state = State::NXDOMAIN;
							} else if (q.type == DNS_TYPE::AAAA && is_nodata_aaaa(q.name)) {
								state = State::NODATA;
							} else if (state == State::FORWARD) {
								dns::Cache *cache = Cache(q.type);
								if (cache) {
									auto entry = cache->find(q.name);
									if (entry) {
										dns::Message sending;
										sending.header = received.header;
										sending.header.flags = 0x8180;
										sending.questions = {q};
										sending.answers = entry->answers;
										sending.authorities = entry->authorities;
										send_dns_message(d, proto, sending, false, true);
										state = State::NONE;
									}
								}
								if (state != State::NONE) {
									state = State::NXDOMAIN;
									const auto local_transaction_id = next_local_transaction_id();
									clean_transaction(local_transaction_id);
									auto Forward = [&](Forwarder const &forwarder){
										std::string query_name = q.name;
										if (m->option.case_randomize) {
											query_name = randomize_case(query_name);
										}
										dns::Message sending;
										sending.header = received.header;
										sending.header.id = m->txid_gen.next();
										sending.header.flags = 0x0100;
										sending.questions = {q};
										sending.questions.front().name = query_name;
										InternalData d2 = *d;
										if (forwarder.af_type == AF_INET) {
											init_sa4(&d2.in4_udp.sa4, (in_addr const *)forwarder.addr, forwarder.port);
										} else if (forwarder.af_type == AF_INET6) {
											init_sa6(&d2.in6_udp.sa6, (in6_addr const *)forwarder.addr, forwarder.port);
										}
										if (send_dns_message(&d2, {forwarder.af_type, SOCK_DGRAM}, sending, true, false)) {
											dns::Query t;
											t.timestamp = misc::get_tick_count();
											t.local_transaction_id = local_transaction_id;
											t.requester_id = received.header.id;
											t.upstream_id = sending.header.id;
											t.type = q.type;
											t.proto = proto;
											if (proto.family() == AF_INET) {
												t.client_sa4 = d->in4_udp.sa4;
											} else if (proto.family() == AF_INET6) {
												t.client_sa6 = d->in6_udp.sa6;
											}
											t.request_name = q.name;
											t.forward_name = query_name;
											push_query(t);
										}
									};
									std::vector<Forwarder> forwarders = get_forwarder();
									size_t n = forwarders.size();
									if (n > 0) {
										size_t i = rand() % n;
										Forwarder const &forwarder1 = forwarders[i];
										if (forwarder1) {
											Forward(forwarder1);
											state = State::NONE;
										}
										if (n > 1) {
											size_t j = (i + 1 + rand() % (n - 1)) % n;
											Forwarder const &forwarder2 = forwarders[j];
											if (forwarder2) {
												Forward(forwarder2);
												state = State::NONE;
											}
										}
									}
								}
							}
						} else {
							state = State::NODATA;
						}
					}
				}
				if (state == State::NXDOMAIN) {
					dns::Message sending = received;
					sending.header.flags = 0x8003;
					sending.questions = received.questions;
					sending.answers.clear();
					sending.authorities.clear();
					send_dns_message(d, proto, sending, false, false);
				} else if (state == State::NODATA) {
					dns::Message sending = received;
					sending.header.flags = 0x8000;
					sending.answers.clear();
					sending.authorities = {dns::Record()};
					dns::Record *r = &sending.authorities.back();
					r->name = q.name;
					r->type = DNS_TYPE::SOA;
					r->clas = q.clas;
					r->ttl = 60;
					r->set_soa(fake_soa());
					send_dns_message(d, proto, sending, false, false);
				}
			}
		} else if (received.header.flags & 0x8000) { // response
			dns::Query q;
			if (take_query(received.header.id, &q)) {
				if (accept_dns_type(q.type)) {
					if (received.questions.size() == 1 && received.questions.front().name == q.forward_name) {
						auto AmendName = [&q](std::string const &name){
							if (stricmp(q.request_name.c_str(), name.c_str()) == 0) {
								return q.request_name;
							} else {
								return misc::strtolower(name);
							}
						};
						dns::Message sending = received;
						sending.header.id = q.requester_id;
						// questions
						for (dns::Question &q3 : sending.questions) {
							q3.name = AmendName(q3.name);
						}
						// answers
						for (dns::Record &a : sending.answers) {
							if (a.clas == DNS_CLASS_IN) {
								if (accept_dns_type(a.type)) {
									a.name = AmendName(a.name);
								}
								if (a.type == DNS_TYPE::CNAME && a.cname()) {
									a.cname()->cname = AmendName(a.cname()->cname);
								} else if (a.type == DNS_TYPE::SOA && a.soa()) {
									a.soa()->nname = AmendName(a.soa()->nname);
									a.soa()->rname = AmendName(a.soa()->rname);
								}
							}
						}
						// send
						auto d2 = *d;
						d2.in4_udp.sa4 = q.client_sa4;
						d2.in6_udp.sa6 = q.client_sa6;
						send_dns_message(&d2, q.proto, sending, false, false);
						// cahce
						dns::Cache *cache = Cache(q.type);
						if (cache) {
							cache->insert(q.forward_name, sending);
						}
					}
				}
			}
		}
	}
}

void Behind::init_socket(void *private_in, ProtocolFamilyType proto)
{
	Behind::InternalData::In *in = static_cast<Behind::InternalData::In *>(private_in);

	int sock = socket(proto.pfamily(), proto.type(), 0);
	if (sock == INVALID_SOCKET) {
		throw STRERROR("socket: ");
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);

	{
		int yes = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
		if (proto.family() == AF_INET6) {
			setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&yes, sizeof(yes));
		}
	}

	int r;
	if (proto.family() == AF_INET) {
		init_sa4(&in->sa4, nullptr, listen_port());
		r = bind(sock, (struct sockaddr *)&in->sa4, sizeof(in->sa4));
	} else {
		init_sa6((sockaddr_in6 *)&in->sa6, nullptr, listen_port());
		r = bind(sock, (struct sockaddr *)&in->sa6, sizeof(in->sa6));
	}
	if (r == SOCKET_ERROR) {
		throw STRERROR("bind: ");
	}

	if (proto.type() == SOCK_DGRAM) {
		in->dgram_fd = sock;
	} else if (proto.type() == SOCK_STREAM) {
		if (listen(sock, 5) == SOCKET_ERROR) {
			throw STRERROR("listen: ");
		}
		in->listen_fd = sock;
	}

	in->family = proto.family();

	InetResolver::Addr addr;
	if (proto.family() == AF_INET) {
		addr.add_in4(&in->sa4.sin_addr.s_addr);
	} else {
		addr.add_in6(&in->sa6.sin6_addr);
	}
	std::string s = addr.to_string(0);
	logprintf(LOG_BOTH, "listen port: %s@%d\n", s.c_str(), ntohs(in->sa4.sin_port));
}

void Behind::add_hosts(std::map<std::string, std::string> const &hosts)
{
	for (auto const &pair : hosts) {
		std::string const &name = pair.first;
		std::string const &value = pair.second;
		InetResolver::Addr addr;
		auto type = parse_inet_address(value, &addr, nullptr);
		if (type == InetResolver::UNDEFINED) {
			logprintf(LOG_DEFAULT, "invalid address in hosts: %s\n", value.c_str());
			continue;
		}
		m->hosts[name] = addr;
	}
}

int Behind::epoll_ctl_add(struct epoll_event *e)
{
	return epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, e->data.fd, e);
}

int Behind::epoll_ctl_del(struct epoll_event *e)
{
	return epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, e->data.fd, e);
}

void Behind::main()
{
	add_hosts(m->option.hosts);

	InternalData d;
	init_socket(&d.in4_udp, {AF_INET, SOCK_DGRAM});
	init_socket(&d.in6_udp, {AF_INET6, SOCK_DGRAM});
	init_socket(&d.in4_tcp, {AF_INET, SOCK_STREAM});
	init_socket(&d.in6_tcp, {AF_INET6, SOCK_STREAM});

	m->socket_mode = SocketMode::EPOLL;

	if (m->socket_mode == SocketMode::SELECT) {
		logprintf(LOG_DEFAULT, "mode: SELECT\n");

		fd_set fds, readfds;
		FD_ZERO(&readfds);
		FD_SET(d.in4_udp.dgram_fd, &readfds);
		FD_SET(d.in6_udp.dgram_fd, &readfds);
		int maxfd = std::max(d.in4_udp.dgram_fd, d.in6_udp.dgram_fd);

		while (1) {
			memcpy(&fds, &readfds, sizeof(fd_set));
			select(maxfd + 1, &fds, nullptr, nullptr, nullptr);

			if (FD_ISSET(d.in4_udp.dgram_fd, &fds)) {
				process(&d, {AF_INET, SOCK_DGRAM});
			}
			if (FD_ISSET(d.in6_udp.dgram_fd, &fds)) {
				process(&d, {AF_INET6, SOCK_DGRAM});
			}

			clean();
		}
	} else if (m->socket_mode == SocketMode::EPOLL) {
		logprintf(LOG_DEFAULT, "mode: EPOLL\n");

		m->epoll_fd = epoll_create1(0);
		if (m->epoll_fd == -1) {
			throw STRERROR("epoll_create1: ");
		}

		auto AddEpoll = [this](Behind::InternalData::In *in, int socktype){
			in->ev = {};
			in->ev.events = EPOLLIN;
			if (socktype == SOCK_DGRAM) {
				in->ev.data.fd = in->dgram_fd;
			} else if (socktype == SOCK_STREAM) {
				in->ev.data.fd = in->listen_fd;
			}
			if (epoll_ctl_add(&in->ev) == -1) {
				throw STRERROR("epoll_ctl: ");
			}
		};
		AddEpoll(&d.in4_udp, SOCK_DGRAM);
		AddEpoll(&d.in6_udp, SOCK_DGRAM);
		AddEpoll(&d.in4_tcp, SOCK_STREAM);
		AddEpoll(&d.in6_tcp, SOCK_STREAM);

		while (1) {
			int n = epoll_wait(m->epoll_fd, m->epoll_events.data(), m->epoll_events.size(), -1);
			if (n == -1) {
				if (errno == EINTR) {
					continue;
				}
				throw STRERROR("epoll_wait: ");
			}
			for (int i = 0; i < n; i++) {
				auto fd = m->epoll_events[i].data.fd;
				if (fd == d.in4_udp.dgram_fd) {
					process(&d, {AF_INET, SOCK_DGRAM});
				} else if (fd == d.in6_udp.dgram_fd) {
					process(&d, {AF_INET6, SOCK_DGRAM});
				} else if (fd == d.in4_tcp.listen_fd) {
					socklen_t len = sizeof(d.in4_tcp.sa4);
					d.in4_tcp.stream_fd = accept(d.in4_tcp.listen_fd, (sockaddr *)&d.in4_tcp.sa4, &len);
					process(&d, {AF_INET, SOCK_STREAM});
					d.in4_tcp.stream_fd = -1;
					closesocket(d.in4_tcp.stream_fd);
				} else if (fd == d.in6_tcp.listen_fd) {
					socklen_t len = sizeof(d.in6_tcp.sa6);
					d.in6_tcp.stream_fd = accept(d.in6_tcp.listen_fd, (sockaddr *)&d.in6_tcp.sa6, &len);
					process(&d, {AF_INET6, SOCK_STREAM});
					closesocket(d.in4_tcp.stream_fd);
					d.in4_tcp.stream_fd = -1;
				}
			}
			clean();
		}
	}

	closesocket(d.in4_udp.dgram_fd);
	closesocket(d.in6_udp.dgram_fd);
	closesocket(d.in4_udp.listen_fd);
	closesocket(d.in6_udp.listen_fd);
}

// test

#define EXPECT_EQ(a, b) assert((a) == (b))

std::string to_string(std::vector<uint8_t> const &buf)
{
	if (buf.empty()) {
		return std::string();
	}
	return std::string((char const *)buf.data(), buf.size());
}

void Behind::test()
{
	std::vector<char> buf;
	char const *file;

	file = "testcase/google_response.bin";
	if (readfile(file, &buf) && !buf.empty()) {
		dns::Message msg;
		char const *begin = buf.data();
		char const *end = begin + buf.size();
		parse_dns_message(begin, end, &msg);
		logprintf(LOG_DEFAULT, "TEST: parsed <%s>, %d questions and %d answers\n", file, (int)msg.questions.size(), (int)msg.answers.size());

		EXPECT_EQ(msg.header.flags, 0x8180);
		EXPECT_EQ(msg.header.ancount, 1);
		EXPECT_EQ(msg.header.qdcount, 1);
		EXPECT_EQ(msg.answers.size(), 1);
		EXPECT_EQ(msg.questions.size(), 1);

		EXPECT_EQ(msg.questions[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(msg.questions[0].type, DNS_TYPE::A);
		EXPECT_EQ(msg.questions[0].name, "www.google.com");

		EXPECT_EQ(msg.answers[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(msg.answers[0].type, DNS_TYPE::A);
		EXPECT_EQ(msg.answers[0].name, "www.google.com");
		EXPECT_EQ(to_string(msg.answers[0].bin), std::string("\x8e\xfa\xc2\xc4", 4));
		EXPECT_EQ(msg.answers[0].ttl, 300);

		{
			Packet response = make_dns_message(msg, false);

			dns::Message msg2;
			char const *begin = response.buffer.data();
			char const *end = begin + response.buffer.size();
			parse_dns_message(begin, end, &msg2);

			EXPECT_EQ(msg2.header.flags, 0x8180);
			EXPECT_EQ(msg2.header.ancount, 1);
			EXPECT_EQ(msg2.header.qdcount, 1);

			EXPECT_EQ(msg.questions, msg2.questions);
			EXPECT_EQ(msg.answers, msg2.answers);
		}
	}

	file = "testcase/amazon_response.bin";
	if (readfile(file, &buf) && !buf.empty()) {
		dns::Message msg;
		char const *begin = buf.data();
		char const *end = begin + buf.size();
		parse_dns_message(begin, end, &msg);
		logprintf(LOG_DEFAULT, "TEST: parsed <%s>, %d msg.questions and %d msg.answers\n", file, (int)msg.questions.size(), (int)msg.answers.size());

		EXPECT_EQ(msg.header.flags, 0x8180);
		EXPECT_EQ(msg.header.ancount, 3);
		EXPECT_EQ(msg.header.qdcount, 1);
		EXPECT_EQ(msg.answers.size(), 3);
		EXPECT_EQ(msg.questions.size(), 1);

		EXPECT_EQ(msg.questions[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(msg.questions[0].type, DNS_TYPE::A);
		EXPECT_EQ(msg.questions[0].name, "www.amazon.co.jp");

		EXPECT_EQ(msg.answers[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(msg.answers[0].type, DNS_TYPE::CNAME);
		EXPECT_EQ(msg.answers[0].name, "www.amazon.co.jp");
		EXPECT_EQ(msg.answers[0].cname()->cname, "tp.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(msg.answers[0].ttl, 300);

		EXPECT_EQ(msg.answers[1].clas, DNS_CLASS_IN);
		EXPECT_EQ(msg.answers[1].type, DNS_TYPE::CNAME);
		EXPECT_EQ(msg.answers[1].name, "tp.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(msg.answers[1].cname()->cname, "cf.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(msg.answers[1].ttl, 300);

		EXPECT_EQ(msg.answers[2].clas, DNS_CLASS_IN);
		EXPECT_EQ(msg.answers[2].type, DNS_TYPE::A);
		EXPECT_EQ(msg.answers[2].name, "cf.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(to_string(msg.answers[2].bin), std::string("\x03\xa8\xfb\x86", 4));
		EXPECT_EQ(msg.answers[2].ttl, 300);

		{
			Packet response = make_dns_message(msg, false);

			dns::Message msg2;
			char const *begin = response.buffer.data();
			char const *end = begin + response.buffer.size();
			parse_dns_message(begin, end, &msg2);

			EXPECT_EQ(msg2.header.flags, 0x8180);
			EXPECT_EQ(msg2.header.ancount, 3);
			EXPECT_EQ(msg2.header.qdcount, 1);

			EXPECT_EQ(msg.questions, msg2.questions);
			EXPECT_EQ(msg.answers, msg2.answers);
		}
	}

	file = "testcase/doubleclick_response.bin";
	if (readfile(file, &buf) && !buf.empty()) {
		dns::Message msg;
		char const *begin = buf.data();
		char const *end = begin + buf.size();
		parse_dns_message(begin, end, &msg);
		logprintf(LOG_DEFAULT, "TEST: parsed <%s>, %d msg.questions and %d msg.answers\n", file, (int)msg.questions.size(), (int)msg.answers.size());

		EXPECT_EQ(msg.header.flags, 0x8003); // NXDOMAIN
		EXPECT_EQ(msg.header.ancount, 0);
		EXPECT_EQ(msg.header.qdcount, 1);
		EXPECT_EQ(msg.answers.size(), 0);
		EXPECT_EQ(msg.questions.size(), 1);

		EXPECT_EQ(msg.questions[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(msg.questions[0].type, DNS_TYPE::A);
		EXPECT_EQ(msg.questions[0].name, "doubleclick.net");
	}
}

