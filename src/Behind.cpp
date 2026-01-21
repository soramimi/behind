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

struct Behind::dns_header_t {
	uint16_t id;
	uint16_t flags = 0x8180;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

struct Behind::query_t {
	uint32_t local_transaction_id;
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

static inline bool operator == (const Behind::question_t &l, const Behind::question_t &r)
{
	if (l.name != r.name) return false;
	if (l.type != r.type) return false;
	if (l.clas != r.clas) return false;
	return true;
}

struct Behind::dns_record_t {
	std::string name;
	DNS_TYPE type = DNS_TYPE::A;
	uint16_t clas = AF_INET;
	uint32_t ttl = 300;
	uint64_t expire = 0;
	std::vector<uint8_t> data;

	std::string to_string() const
	{
		if (type == DNS_TYPE::A && data.size() == 4) {
			struct sockaddr_in a = {};
			a.sin_addr.s_addr = *(uint32_t *)data.data();
			return addr_to_string(AF_INET, (struct sockaddr *)&a);
		} else if (type == DNS_TYPE::AAAA && data.size() == 16) {
			struct sockaddr_in6 a = {};
			memcpy(&a.sin6_addr.s6_addr, data.data(), 16);
			return addr_to_string(AF_INET6, (struct sockaddr *)&a);
		} else if (type == DNS_TYPE::CNAME && data.size() < 255) {
			std::string_view sv((char const *)data.data(), data.size());
			return std::string(sv);
		}
		return {};
	}
};

static inline bool operator == (const Behind::dns_record_t &l, const Behind::dns_record_t &r)
{
	if (l.type != r.type) return false;
	if (l.clas != r.clas) return false;
	if (l.data.size() != r.data.size()) return false;
	if (memcmp(l.data.data(), r.data.data(), l.data.size()) != 0) return false;
	return true;
}

class Behind::dns_cache_t {
public:
	struct Item {
		std::string key;
		uint64_t timestamp = 0;
		uint64_t expire = 0;
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
	struct Entry {
		std::vector<Behind::dns_record_t> records;
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
				ret.records = items_[it->second].records;
				for (size_t i = 0; i < ret.records.size(); i++) {
					auto exp = ret.records[i].expire;
					if (now < exp) {
						ret.records[i].ttl = (uint32_t)((exp - now) / 1000);
					} else {
						ret.records[i].ttl = 0;
					}
				}
				return ret;
			}
		}
		return std::nullopt;
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
		item->records = records;
		for (size_t i = 0; i < item->records.size(); i++) {
			item->records[i].expire = now + item->records[i].ttl * 1000;
			item->expire = std::min(item->expire, item->records[i].expire);
		}
	}
};

struct Behind::Private {
	Option option;
	Hosts hosts;
	uint32_t local_transaction_id = 0;
	TransactionIdGenerator txid_gen;
	InetResolver resolver;
	int ttl = 5 * 60;
	struct {
		Behind::dns_cache_t a;
		Behind::dns_cache_t aaaa;
	} dns_cache;
	std::vector<Behind::query_t> queries;
	std::vector<Forwarder> forwarder;

	struct D {
		int sock4;
		int sock6;
		struct sockaddr_in sa4;
		struct sockaddr_in6 sa6;

	};
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

bool Behind::write_dns_answer_rr(std::vector<char> *out, std::map<std::string, size_t> *namemap, std::string const &name, uint16_t clas, uint32_t ttl, const Behind::dns_record_t &item)
{
	write_name(out, namemap, name);
	write_us(out, (int)item.type);
	write_us(out, clas);
	write_ul(out, ttl);

	int len = 0;
	len = item.data.size();
	if (item.type == DNS_TYPE::CNAME) {
		std::string cname((char const *)item.data.data(), item.data.size());
		size_t i = out->size();
		write_us(out, 0);
		write_name(out, namemap, cname);
		write_us(&out->at(i), out->size() - i - 2);
	} else {
		if (item.type == DNS_TYPE::A && len == 4) {
			// len = 4;
		} else if (item.type == DNS_TYPE::AAAA && len == 16) {
			// len = 16;
		} else {
			return false;
		}
		write_us(out, len);
		write(out, (char const *)item.data.data(), len);
	}
	return true;
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
		int port = 0;
		size_t len = parse_int(p, &port);
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
		addr.addr.emplace_back();
		addr.addr.front().resize(4);
		memcpy(addr.addr.front().data(), &sa4.sin_addr.s_addr, 4);
	} else if (in6) {
		addr.type = InetResolver::IN6;
		struct sockaddr_in6 sa6 = {};
		inet_pton(AF_INET6, name.c_str(), &sa6.sin6_addr);
		addr.addr.emplace_back();
		addr.addr.front().resize(16);
		memcpy(addr.addr.front().data(), sa6.sin6_addr.s6_addr, 16);
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
		int port = 53;

		InetResolver::Type type = parse_inet_address(name, &addr, &port);

		m->resolver.resolve(name.c_str(), type, &addr);

		Forwarder forwarder;
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
		if (now - m->queries[i].time >= 1000) { // 1 second
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

bool Behind::take_query(uint16_t id, Behind::query_t *out)
{
	for (query_t const &q : m->queries) {
		if (id == q.upstream_id) {
			*out = q;
			clean_transaction(q.local_transaction_id);
			return true;
		}
	}
	return false;
}

void Behind::push_query(const Behind::query_t &query)
{
	take_query(query.upstream_id, 0);
	m->queries.push_back(query);
}

void Behind::parse_dns_packet(const char *begin, const char *end, Behind::dns_header_t *header, std::vector<Behind::question_t> *questions, std::vector<Behind::dns_record_t> *answers)
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
		dns_record_t a;
		int n = decode_name(begin, end, ptr, &a.name);
		if (n > 0 && !a.name.empty()) {
			ptr += n;
		}
		if (ptr + 10 <= end) {
			uint16_t tmp[5];
			memcpy(tmp, ptr, 10);
			a.type = (DNS_TYPE)ntohs(tmp[0]);
			a.clas = ntohs(tmp[1]);
			// a.ttl = ntohl(*(uint32_t *)&tmp[2]); // -Wstrict-aliasing
			memcpy(&a.ttl, tmp + 2, 4);
			a.ttl = ntohl(a.ttl);
			uint16_t rdlen = ntohs(tmp[4]);
			ptr += 10;
			if (ptr + rdlen <= end) {
				auto it = answers->insert(answers->end(), dns_record_t());
				*it = a;
				if ((a.type == DNS_TYPE::A && rdlen == 4) || (a.type == DNS_TYPE::AAAA && rdlen == 16)) {
					if (rdlen > 0) {
						it->data.resize(rdlen);
						memcpy(it->data.data(), ptr, rdlen);
						ptr += rdlen;
					}
				} else if (a.type == DNS_TYPE::CNAME && rdlen < 255) {
					if (rdlen > 0) {
						std::string name;
						int n = decode_name(begin, end, ptr, &name);
						if (n > 0 && !name.empty()) {
							name = misc::strtolower(name);
							it->data.resize(name.size());
							memcpy(it->data.data(), name.c_str(), name.size());
						}
						ptr += rdlen;
					}
				}
			}
		}
	}
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
	sa_family_t family = AF_UNSPEC;
	union {
		sockaddr_in sa4;
		sockaddr_in6 sa6;
	} to;
	void set_sa4(struct sockaddr_in const *sa)
	{
		family = AF_INET;
		memcpy(&to.sa4, sa, sizeof(sockaddr_in));
	}
	void set_sa6(struct sockaddr_in6 const *sa)
	{
		family = AF_INET6;
		memcpy(&to.sa6, sa, sizeof(sockaddr_in6));
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
		const int len = 4;
		sockaddr_in sa;
		init_sa4(&sa, addr, port);
		set_sa4(&sa);
	}
	void set_sa6(in6_addr const *addr, int port)
	{
		const int len = 16;
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
	ssize_t sendto(void const *buf, size_t len)
	{
		int flags = 0;
		if (family == AF_INET) {
			return ::sendto(sock, buf, len, flags, (struct sockaddr *)&to.sa4, sizeof(sockaddr_in));
		}
		if (family == AF_INET6) {
			return ::sendto(sock, buf, len, flags, (struct sockaddr *)&to.sa6, sizeof(sockaddr_in6));
		}
		return -1;
	}
};

bool Behind::is_nxdomain(std::string const &name) const
{
	return m->option.domain_filter.find(name) == DomainFilter::NXDOMAIN;
}

char const *dns_type_to_string(DNS_TYPE type)
{
	switch (type) {
	case DNS_TYPE::A:
		return "A";
	case DNS_TYPE::CNAME:
		return "CNAME";
	case DNS_TYPE::PTR:
		return "PTR";
	case DNS_TYPE::AAAA:
		return "AAAA";
	default:
		return "?";
	}
}

struct Behind::ResponseData {
	Behind::question_t q;
	std::vector<char> buffer;
	operator bool () const
	{
		return !buffer.empty();
	}
};

Behind::ResponseData Behind::make_response(void *private_d, dns_header_t const &header, std::vector<question_t> const &questions, std::vector<dns_record_t> const &rec)
{
	ResponseData ret;
	std::map<std::string, size_t> namemap;

	uint16_t ancount = uint16_t(std::min(rec.size(), (size_t)16));

	write_dns_header(&ret.buffer, header.id, header.flags, 1, ancount, 0, 0);

	for (auto it = questions.begin(); it != questions.end(); it++) {
		question_t const &q = *it;
		write_dns_question_rr(&ret.buffer, &namemap, q.name, q.type, q.clas);
	}

	if (!questions.empty()) {
		ret.q = questions.front();
	}

	for (int i = 0; i < ancount; i++) {
		dns_record_t const &r = rec[i];
		std::string name = stricmp(ret.q.name.c_str(), r.name.c_str()) == 0 ? ret.q.name : misc::strtolower(r.name);
		if (!write_dns_answer_rr(&ret.buffer, &namemap, name, ret.q.clas, r.ttl, r)) {
			return {};
		}
	}

	return ret;
}

bool Behind::send_response(void *private_d, int family, dns_header_t const &header, std::vector<question_t> const &questions, std::vector<dns_record_t> const &rec, bool forward, bool from_cache)
{
	Private::D *d = static_cast<Private::D *>(private_d);

	ResponseData response = make_response(private_d, header, questions, rec);
	if (!response) return false;

	std::string client;
	SendTo sender;
	if (family == AF_INET) {
		sender.set_sa4(d->sock4, &d->sa4);
	} else if (family == AF_INET6) {
		sender.set_sa6(d->sock6, &d->sa6);
	}
	bool ok = sender.sendto(&response.buffer[0], response.buffer.size()) == response.buffer.size();
	client = sender.addr_to_string();

	char const *comment = "";
	if (from_cache) {
		comment = " (from cache)";
	}

	char const *qtype = dns_type_to_string(response.q.type);
	if (forward) {
		logprintf(LOG_DEFAULT, "F: %s\n", response.q.name.c_str());
	} else if ((header.flags & 0x000f) == 3) { // NXDOMAIN
		logprintf(LOG_DEFAULT, "R: <<%s %s NXDOMAIN>> to %s\n"
				  , response.q.name.c_str()
				  , qtype
				  , client.c_str()
				  );
	} else if (rec.size() > 0) {
		for (int i = 0; i < rec.size(); i++) {
			dns_record_t const &r = rec[i];
			std::string name = misc::strtolower(response.q.name);
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
				  , response.q.name.c_str()
				  , qtype
				  , client.c_str()
				  , comment
				  );
	}

	if (0) {
		if (header.flags & 0x8000) {
			if (stricmp(response.q.name.c_str(), "www.google.com") == 0) {
				char const *path = "testcase/google_response.bin";
				writefile(path, &response.buffer);
			} else if (stricmp(response.q.name.c_str(), "doubleclick.net") == 0) {
				char const *path = "testcase/doubleclick_response.bin";
				writefile(path, &response.buffer);
			} else if (stricmp(response.q.name.c_str(), "www.soramimi.jp") == 0) {
				char const *path = "testcase/soramimi_response.bin";
				writefile(path, &response.buffer);
			} else if (stricmp(response.q.name.c_str(), "www.amazon.co.jp") == 0) {
				char const *path = "testcase/amazon_response.bin";
				writefile(path, &response.buffer);
			}
		} else {
			if (stricmp(response.q.name.c_str(), "www.google.com") == 0) {
				char const *path = "testcase/google_query.bin";
				writefile(path, &response.buffer);
			} else if (stricmp(response.q.name.c_str(), "doubleclick.net") == 0) {
				char const *path = "testcase/doubleclick_query.bin";
				writefile(path, &response.buffer);
			} else if (stricmp(response.q.name.c_str(), "www.soramimi.jp") == 0) {
				char const *path = "testcase/soramimi_query.bin";
				writefile(path, &response.buffer);
			} else if (stricmp(response.q.name.c_str(), "www.amazon.co.jp") == 0) {
				char const *path = "testcase/amazon_query.bin";
				writefile(path, &response.buffer);
			}
		}
	}

	return ok;
}

std::vector<Behind::dns_record_t> Behind::make_records(query_t const &q, std::vector<dns_record_t> const &answers)
{
	std::vector<dns_record_t> records;
	records.reserve(10);
	for (auto it = answers.begin(); it != answers.end(); it++) {
		dns_record_t const &a = *it;
		if (a.clas == DNS_CLASS_IN) {
			auto size = a.data.size();
			if ((a.type == DNS_TYPE::A && size == 4) || (a.type == DNS_TYPE::AAAA && size == 16) || (a.type == DNS_TYPE::CNAME && size < 255)) {
				dns_record_t item;
				item.name = stricmp(q.request_name.c_str(), a.name.c_str()) == 0 ? q.request_name : misc::strtolower(a.name);
				item.type = a.type;
				item.data = a.data;
				item.ttl = a.ttl;
				records.push_back(item);
			}
		}
	}
	return records;
}

InetResolver::Addr const *Behind::find_host(std::string const &name) const
{
	return m->hosts.find(name);
}

uint32_t Behind::next_local_transaction_id()
{
	return m->local_transaction_id++;
}

void Behind::process(void *private_d, int family)
{
	Private::D *d = static_cast<Private::D *>(private_d);

	char buf[1500];
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
		std::vector<question_t> questions;
		std::vector<dns_record_t> answers;
		parse_dns_packet(buf, buf + len, &header, &questions, &answers);

		if ((header.flags & 0xf800) == 0x0000) { // standard query
			for (auto it = questions.begin(); it != questions.end(); it++) {
				question_t const &q = *it;
				char const *qtype_str = dns_type_to_string(q.type);

				dns_cache_t *cache = nullptr;
				if (q.type == DNS_TYPE::A) {
					cache = &m->dns_cache.a;
				} else if (q.type == DNS_TYPE::AAAA) {
					cache = &m->dns_cache.aaaa;
				}

				enum class State {
					NONE,
					FORWARD,
					NXDOMAIN,
				};
				State state = State::NONE;
				if (!q.name.empty()) {
					if (q.clas == DNS_CLASS_IN) {
						if (q.type == DNS_TYPE::A || q.type == DNS_TYPE::AAAA) {
							logprintf(LOG_DEFAULT, "Q: %s %s\n", q.name.c_str(), qtype_str);
							state = State::FORWARD;
							{
								// check known hosts
								InetResolver::Addr const *addr = m->hosts.find(q.name);
								if (addr) {
									state = State::NONE;
									std::vector<dns_record_t> rec;
									if ((q.type == DNS_TYPE::A && addr->type == InetResolver::IN4) || (q.type == DNS_TYPE::AAAA && addr->type == InetResolver::IN6)) {
										dns_record_t r;
										r.name = q.name;
										r.type = q.type;
										r.ttl = ttl();
										for (std::vector<uint8_t> const &a : addr->addr) {
											r.data = a;
											rec.push_back(r);
										}
										auto h = header;
										h.flags = 0x8180;
										send_response(d, family, h, {q}, rec, false, false);
									} else {
										state = State::NXDOMAIN;
									}
								}
							}
							if (state == State::NXDOMAIN) {
								// nop
							} else if (is_nxdomain(q.name)) {
								state = State::NXDOMAIN;
							} else if (state == State::FORWARD) {
								if (cache) {
									auto entry = cache->find(q.name);
									if (entry) {
										auto h = header;
										h.flags = 0x8180;
										send_response(d, family, h, {q}, entry->records, false, true);
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
										dns_header_t h = header;
										h.id = m->txid_gen.next();
										h.flags = 0x0100;
										question_t q2 = q;
										q2.name = query_name;
										Private::D d2 = *d;
										if (forwarder.af_type == AF_INET) {
											init_sa4(&d2.sa4, (in_addr const *)forwarder.addr, forwarder.port);
										} else if (forwarder.af_type == AF_INET6) {
											init_sa6(&d2.sa6, (in6_addr const *)forwarder.addr, forwarder.port);
										}
										if (send_response(&d2, forwarder.af_type, h, {q2}, {}, true, false)) {
											query_t t;
											t.local_transaction_id = local_transaction_id;
											t.time = misc::get_tick_count();
											t.requester_id = header.id;
											t.upstream_id = h.id;
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
						}
					}
				}
				if (state == State::NXDOMAIN) {
					auto h = header;
					h.flags = 0x8003;
					send_response(private_d, family, h, questions, {}, false, false);
				}
			}
		} else if (header.flags & 0x8000) { // response
			query_t q;
			if (take_query(header.id, &q)) {
				if (q.type == DNS_TYPE::A || q.type == DNS_TYPE::AAAA) {
					if (questions.size() == 1 && questions.front().name == q.forward_name) {
						std::string qname = questions.front().name;
						qname = stricmp(q.request_name.c_str(), qname.c_str()) == 0 ? q.request_name : misc::strtolower(qname);
						// make answer
						std::vector<dns_record_t> records = make_records(q, answers);
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
						auto d2 = *d;
						d2.sa4 = q.client_sa4;
						d2.sa6 = q.client_sa6;
						auto h = header;
						h.id = q.requester_id;
						std::vector<question_t> questions2 = questions;
						for (question_t &q3 : questions2) {
							q3.name = stricmp(q.request_name.c_str(), q3.name.c_str()) == 0 ? q.request_name : misc::strtolower(q3.name);
						}
						send_response(&d2, q.client_family, h, questions2, records, false, false);
					}
				}
			}
		}
	}
}

std::string to_string(std::vector<uint8_t> const &buf)
{
	if (buf.empty()) {
		return std::string();
	}
	return std::string((char const *)buf.data(), buf.size());
}

#define EXPECT_EQ(a, b) assert((a) == (b))

void Behind::test()
{
	std::vector<char> buf;
	char const *file;

	file = "testcase/google_response.bin";
	if (readfile(file, &buf) && !buf.empty()) {
		char const *begin = buf.data();
		char const *end = begin + buf.size();
		Behind::dns_header_t header;
		std::vector<Behind::question_t> questions;
		std::vector<Behind::dns_record_t> answers;
		parse_dns_packet(begin, end, &header, &questions, &answers);
		logprintf(LOG_DEFAULT, "TEST: parsed <%s>, %d questions and %d answers\n", file, (int)questions.size(), (int)answers.size());

		EXPECT_EQ(header.flags, 0x8180);
		EXPECT_EQ(header.ancount, 1);
		EXPECT_EQ(header.qdcount, 1);
		EXPECT_EQ(answers.size(), 1);
		EXPECT_EQ(questions.size(), 1);

		EXPECT_EQ(questions[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(questions[0].type, DNS_TYPE::A);
		EXPECT_EQ(questions[0].name, "www.google.com");

		EXPECT_EQ(answers[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(answers[0].type, DNS_TYPE::A);
		EXPECT_EQ(answers[0].name, "www.google.com");
		EXPECT_EQ(to_string(answers[0].data), std::string("\x8e\xfa\xc2\xc4", 4));
		EXPECT_EQ(answers[0].ttl, 300);

		{
			Private::D d;

			query_t q;
			q.request_name = questions[0].name;
			std::vector<dns_record_t> rec = make_records(q, answers);
			ResponseData response = make_response(&d, header, questions, rec);

			Behind::dns_header_t header2;
			std::vector<Behind::question_t> questions2;
			std::vector<Behind::dns_record_t> answers2;
			char const *begin = response.buffer.data();
			char const *end = begin + response.buffer.size();
			parse_dns_packet(begin, end, &header2, &questions2, &answers2);

			EXPECT_EQ(header2.flags, 0x8180);
			EXPECT_EQ(header2.ancount, 1);
			EXPECT_EQ(header2.qdcount, 1);

			EXPECT_EQ(questions, questions2);
			EXPECT_EQ(answers, answers2);
		}
	}

	file = "testcase/amazon_response.bin";
	if (readfile(file, &buf) && !buf.empty()) {
		char const *begin = buf.data();
		char const *end = begin + buf.size();
		Behind::dns_header_t header;
		std::vector<Behind::question_t> questions;
		std::vector<Behind::dns_record_t> answers;
		parse_dns_packet(begin, end, &header, &questions, &answers);
		logprintf(LOG_DEFAULT, "TEST: parsed <%s>, %d questions and %d answers\n", file, (int)questions.size(), (int)answers.size());

		EXPECT_EQ(header.flags, 0x8180);
		EXPECT_EQ(header.ancount, 3);
		EXPECT_EQ(header.qdcount, 1);
		EXPECT_EQ(answers.size(), 3);
		EXPECT_EQ(questions.size(), 1);

		EXPECT_EQ(questions[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(questions[0].type, DNS_TYPE::A);
		EXPECT_EQ(questions[0].name, "www.amazon.co.jp");

		EXPECT_EQ(answers[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(answers[0].type, DNS_TYPE::CNAME);
		EXPECT_EQ(answers[0].name, "www.amazon.co.jp");
		EXPECT_EQ(to_string(answers[0].data), "tp.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(answers[0].ttl, 300);

		EXPECT_EQ(answers[1].clas, DNS_CLASS_IN);
		EXPECT_EQ(answers[1].type, DNS_TYPE::CNAME);
		EXPECT_EQ(answers[1].name, "tp.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(to_string(answers[1].data), "cf.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(answers[1].ttl, 300);

		EXPECT_EQ(answers[2].clas, DNS_CLASS_IN);
		EXPECT_EQ(answers[2].type, DNS_TYPE::A);
		EXPECT_EQ(answers[2].name, "cf.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(to_string(answers[2].data), std::string("\x03\xa8\xfb\x86", 4));
		EXPECT_EQ(answers[2].ttl, 300);

		{
			Private::D d;

			query_t q;
			q.request_name = questions[0].name;
			std::vector<dns_record_t> rec = make_records(q, answers);
			ResponseData response = make_response(&d, header, questions, rec);

			Behind::dns_header_t header2;
			std::vector<Behind::question_t> questions2;
			std::vector<Behind::dns_record_t> answers2;
			char const *begin = response.buffer.data();
			char const *end = begin + response.buffer.size();
			parse_dns_packet(begin, end, &header2, &questions2, &answers2);

			EXPECT_EQ(header2.flags, 0x8180);
			EXPECT_EQ(header2.ancount, 3);
			EXPECT_EQ(header2.qdcount, 1);

			EXPECT_EQ(questions, questions2);
			EXPECT_EQ(answers, answers2);
		}
	}

	file = "testcase/doubleclick_response.bin";
	if (readfile(file, &buf) && !buf.empty()) {
		char const *begin = buf.data();
		char const *end = begin + buf.size();
		Behind::dns_header_t header;
		std::vector<Behind::question_t> questions;
		std::vector<Behind::dns_record_t> answers;
		parse_dns_packet(begin, end, &header, &questions, &answers);
		logprintf(LOG_DEFAULT, "TEST: parsed <%s>, %d questions and %d answers\n", file, (int)questions.size(), (int)answers.size());

		EXPECT_EQ(header.flags, 0x8003); // NXDOMAIN
		EXPECT_EQ(header.ancount, 0);
		EXPECT_EQ(header.qdcount, 1);
		EXPECT_EQ(answers.size(), 0);
		EXPECT_EQ(questions.size(), 1);

		EXPECT_EQ(questions[0].clas, DNS_CLASS_IN);
		EXPECT_EQ(questions[0].type, DNS_TYPE::A);
		EXPECT_EQ(questions[0].name, "doubleclick.net");
	}
}

void Behind::init_socket4(void *private_d)
{
	Private::D *d = static_cast<Private::D *>(private_d);

	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET) {
		throw STRERROR("socket: ");
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);

	{
		int yes = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
	}

	init_sa4(&d->sa4, nullptr, listen_port());
	if (bind(sock, (struct sockaddr *)&d->sa4, sizeof(d->sa4)) == SOCKET_ERROR) {
		throw STRERROR("bind: ");
	}

	d->sock4 = sock;
}

void Behind::init_socket6(void *private_d)
{
	Private::D *d = static_cast<Private::D *>(private_d);

	int sock = socket(PF_INET6, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET) {
		throw STRERROR("socket: ");
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);

	{
		int yes = 1;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&yes, sizeof(yes));
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
	}

	init_sa6(&d->sa6, nullptr, listen_port());
	if (bind(sock, (struct sockaddr *)&d->sa6, sizeof(d->sa6)) == SOCKET_ERROR) {
		throw STRERROR("bind: ");
	}

	d->sock6 = sock;
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

void Behind::main()
{
	Private::D d;

	add_hosts(m->option.hosts);

	enum Mode {
		SELECT,
		EPOLL,
	};
	const Mode mode = EPOLL;

	init_socket4(&d);
	init_socket6(&d);

	if (mode == SELECT) {

		logprintf(LOG_DEFAULT, "mode: SELECT\n");

		fd_set fds, readfds;
		FD_ZERO(&readfds);
		FD_SET(d.sock4, &readfds);
		FD_SET(d.sock6, &readfds);
		int maxfd = std::max(d.sock4, d.sock6);

		while (1) {
			memcpy(&fds, &readfds, sizeof(fd_set));
			select(maxfd + 1, &fds, NULL, NULL, NULL);

			if (FD_ISSET(d.sock4, &fds)) {
				process(&d, AF_INET);
			}
			if (FD_ISSET(d.sock6, &fds)) {
				process(&d, AF_INET6);
			}

			clean();
		}
	} else if (mode == EPOLL) {

		logprintf(LOG_DEFAULT, "mode: EPOLL\n");

		struct epoll_event events[2];
		struct epoll_event ev4 = {};
		struct epoll_event ev6 = {};

		int epoll_fd = epoll_create1(0);
		if (epoll_fd == -1) {
			throw STRERROR("epoll_create1: ");
		}

		auto SetupEpoll = [](int sock, int epoll_fd, struct epoll_event *e){
			e->events = EPOLLIN;
			e->data.fd = sock;
			if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, e) == -1) {
				throw STRERROR("epoll_ctl: ");
			}
		};
		SetupEpoll(d.sock4, epoll_fd, &ev4);
		SetupEpoll(d.sock6, epoll_fd, &ev6);

		while (1) {
			int nfds = epoll_wait(epoll_fd, events, 2, -1);
			if (nfds == -1) {
				if (errno == EINTR) {
					continue;
				}
				throw STRERROR("epoll_wait: ");
			}
			for (int i = 0; i < nfds; i++) {
				if (events[i].data.fd == d.sock4) {
					process(&d, AF_INET);
				} else if (events[i].data.fd == d.sock6) {
					process(&d, AF_INET6);
				}
			}
			clean();
		}
	}

	closesocket(d.sock4);
	closesocket(d.sock6);
}


