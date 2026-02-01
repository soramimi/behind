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
#include <optional>
#include <regex>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

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
	uint16_t id = 0;
	uint16_t flags = 0x8180;
	uint16_t qdcount = 0;
	uint16_t ancount = 0;
	uint16_t nscount = 0;
	uint16_t arcount = 0;
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

struct Behind::Task {
	Operation op = Operation::NONE;
	uint64_t timestamp;
	uint32_t local_transaction_id;
	uint16_t upstream_id;
	uint16_t requester_id;
	DNS_TYPE type = DNS_TYPE::A;
	ProtocolFamilyType client_proto;
	ProtocolFamilyType upstream_proto;
	int upstream_fd = -1;
	struct epoll_event ev;
	union {
		sockaddr_in client_sa4;
		sockaddr_in6 client_sa6;
	};
	std::string request_name;
	std::string forward_name;
};

struct Behind::Private {
	Option option;
	Hosts hosts;
	uint32_t local_transaction_id = 0;
	TransactionIdGenerator txid_gen;
	InetResolver resolver;

	Behind::SocketMode socket_mode;
	fd_set readfds;
	int epoll_fd = -1;
	std::vector<int> poll_fds;
	std::vector<epoll_event> epoll_events{10};

	int ttl = 5 * 60;
	struct {
		dns::Cache a;
		dns::Cache aaaa;
		dns::Cache soa;
	} dns_cache;
	std::vector<Task> queries;
	std::vector<Forwarder> forwarders;
};

struct Behind::InternalData {
	struct In {
		int listener_fd = -1;
		int fd = -1;
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

bool Behind::write_name(std::vector<char> *out, NameMap *namemap, const std::string &name)
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
			namemap->set(srcptr, out->size());
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

void Behind::write_dns_question_rr(std::vector<char> *out, NameMap *namemap, const std::string &name, DNS_TYPE type, uint16_t clas)
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

bool Behind::write_dns_answer_rr(std::vector<char> *out, NameMap *namemap, std::string const &name, uint16_t clas, uint32_t ttl, const dns::Record &item)
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

std::vector<Forwarder const *> Behind::choose_forwarder(int max) const
{
	std::vector<Forwarder const *> ret;
	for (Forwarder const &f : m->forwarders) {
		if (f) {
			ret.push_back(&f);
		}
	}
	if (max < 0) return ret;
	size_t n = ret.size();
	size_t m = std::min((size_t)max, n);
	for (size_t i = 0; i < m; i++) {
		size_t j = i + rand() % (n - i);
		std::swap(ret[i], ret[j]);
	}
	ret.resize(m);
	return ret;
}

uint16_t Behind::next_txid()
{
	return m->txid_gen.next();
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

		m->forwarders.push_back(forwarder);
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

std::optional<Behind::Task> Behind::take_task_by_id(uint16_t upstream_id)
{
	for (Task const &q : m->queries) {
		if (upstream_id == q.upstream_id) {
			std::optional<Task> ret = q;
			clean_transaction(q.local_transaction_id);
			return ret;
		}
	}
	return std::nullopt;
}

std::optional<Behind::Task> Behind::take_task_by_fd(int fd)
{
	for (Task const &q : m->queries) {
		if (q.ev.data.fd == fd) {
			std::optional<Task> ret = q;
			clean_transaction(q.local_transaction_id);
			return ret;
		}
	}
	return std::nullopt;
}

void Behind::push_task(const Task &task)
{
	take_task_by_id(task.upstream_id);
	m->queries.push_back(task);
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

struct Sender {
	int sock = -1;
	ProtocolFamilyType proto;
	std::string addr_string;
	Sender(ProtocolFamilyType const &proto)
		: proto(proto)
	{
	}
	void addr_to_string(struct sockaddr *sa)
	{
		addr_string = ::addr_to_string(proto.family(), sa);
	}
	ssize_t send(Behind::InternalData *d, void const *buf, size_t len)
	{
		int flags = 0;
		if (proto.is_dgram()) {
			if (proto.is_inet4()) {
				addr_to_string((struct sockaddr *)&d->in4_udp.sa4);
				return ::sendto(d->in4_udp.fd, buf, len, flags, (struct sockaddr *)&d->in4_udp.sa4, sizeof(sockaddr_in));
			} else if (proto.is_inet6()) {
				addr_to_string((struct sockaddr *)&d->in6_udp.sa6);
				return ::sendto(d->in6_udp.fd, buf, len, flags, (struct sockaddr *)&d->in6_udp.sa6, sizeof(sockaddr_in6));
			}
		} else if (proto.is_stream()) {
			int sock = -1;
			if (proto.is_inet4()) {
				sock = d->in4_tcp.fd;
			} else if (proto.is_inet6()) {
				sock = d->in6_tcp.fd;
			} else {
				return -1;
			}
			return ::send(sock, buf, len, flags);
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
	NameMap namemap;

	if (tcp) {
		ret.buffer.resize(2);
		namemap.set_offset(2);
	}

	auto LimitCount = [](size_t n){
		return uint16_t(std::min(n, (size_t)100));
	};

	dns::Header h = msg.header;
	h.qdcount = LimitCount(msg.questions.size());
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
		*(uint16_t *)ret.buffer.data() = htons((uint16_t)ret.buffer.size() - namemap.offset());
	} else {
		if (ret.buffer.size() > 512) {
			dns::Header *header = (dns::Header *)ret.buffer.data();
			header->flags |= htons(0x0200); // TC
			ret.buffer.resize(512);
		}
	}

	return ret;
}

bool Behind::send_dns_message(InternalData *d, ProtocolFamilyType const &proto, dns::Message const &msg, bool forward, bool from_cache)
{
	bool tcp = proto.socktype() == SOCK_STREAM;
	Packet packet = make_dns_message(msg, tcp);
	if (!packet) return false;

	Sender sender(proto);
	bool ok = sender.send(d, &packet.buffer[0], packet.buffer.size()) == (ssize_t)packet.buffer.size();
	std::string client = sender.addr_string;

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

std::vector<char> Behind::read(InternalData *d, ProtocolFamilyType const &proto)
{
	std::vector<char> buf;
	int len = 0;
	if (proto.is_dgram()) {
		int sock = INVALID_SOCKET;
		struct sockaddr *sa = nullptr;
		socklen_t salen = 0;
		if (proto.is_inet4()) {
			sock = d->in4_udp.fd;
			sa = (struct sockaddr *)&d->in4_udp.sa4;
			salen = sizeof(sockaddr_in);
		} else if (proto.is_inet6()) {
			sock = d->in6_udp.fd;
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
	} else if (proto.is_stream()) {
		int sock = INVALID_SOCKET;
		if (proto.is_inet4()) {
			sock = d->in4_tcp.fd;
		} else if (proto.is_inet6()) {
			sock = d->in6_tcp.fd;
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

dns::Cache *Behind::get_cache(DNS_TYPE type)
{
	switch (type) {
	case DNS_TYPE::A:    return &m->dns_cache.a;
	case DNS_TYPE::AAAA: return &m->dns_cache.aaaa;
	case DNS_TYPE::SOA:  return &m->dns_cache.soa;
	}
	return nullptr;
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

void Behind::forward_udp(InternalData const &d, ProtocolFamilyType const &client_proto, dns::Header const &header, dns::Question const &question, uint32_t local_transaction_id, Forwarder const &forwarder)
{
	std::string query_name = question.name;
	if (m->option.case_randomize) {
		query_name = randomize_case(query_name);
	}

	dns::Message sending;
	sending.header.id = next_txid();
	sending.header.flags = 0x0100;
	sending.questions = {question};
	sending.questions.front().name = query_name;

	int sock = -1;
	{
		int pf = PF_INET;
		if (forwarder.is_inet6()) {
			pf = PF_INET6;
		}
		sock = socket(pf, SOCK_DGRAM, 0);
		if (sock == INVALID_SOCKET) {
			throw STRERROR("socket: ");
		}

		fcntl(sock, F_SETFL, O_NONBLOCK);

		{
			int yes = 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
			if (pf == PF_INET6) {
				setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&yes, sizeof(yes));
			}
		}
	}

	InternalData d2;
	if (forwarder.is_inet4()) {
		init_sa4(&d2.in4_udp.sa4, (in_addr const *)forwarder.addr, forwarder.port);
		d2.in4_udp.fd = sock;
	} else if (forwarder.is_inet6()) {
		init_sa6(&d2.in6_udp.sa6, (in6_addr const *)forwarder.addr, forwarder.port);
		d2.in6_udp.fd = sock;
	}

	if (send_dns_message(&d2, {forwarder.af_type, SOCK_DGRAM}, sending, true, false)) {
		Task t;
		t.upstream_fd = sock;
		t.op = Operation::REPLY_TO_CLIENT_UDP;
		t.timestamp = misc::get_tick_count();
		t.local_transaction_id = local_transaction_id;
		t.requester_id = header.id;
		t.upstream_id = sending.header.id;
		t.type = question.type;
		t.client_proto = client_proto;
		t.upstream_proto = {forwarder.af_type, SOCK_DGRAM};
		if (client_proto.is_inet4()) {
			t.client_sa4 = d.in4_udp.sa4;
		} else if (client_proto.is_inet6()) {
			t.client_sa6 = d.in6_udp.sa6;
		}
		t.request_name = question.name;
		t.forward_name = query_name;

		t.ev = {};
		t.ev.events = EPOLLIN;
		t.ev.data.fd = t.upstream_fd;
		push_task(t);

		ctl_add(t.upstream_fd, &t.ev);
	}
}

bool Behind::forward_tcp(InternalData *d, ProtocolFamilyType const &client_proto, uint16_t client_request_id, dns::Header const &header, dns::Question const &question, uint32_t local_transaction_id, Forwarder const &forwarder)
{
	std::string query_name = question.name;
	if (m->option.case_randomize) {
		query_name = randomize_case(query_name);
	}

	ProtocolFamilyType upstream_proto = {forwarder.af_type, SOCK_STREAM};

	InternalData::In in;

	sockaddr *sa = nullptr;
	socklen_t salen = 0;
	if (upstream_proto.is_inet4()) {
		init_sa4(&in.sa4, (in_addr *)forwarder.addr, forwarder.port);
		sa = (sockaddr *)&in.sa4;
		salen = sizeof(in.sa4);
	} else if (upstream_proto.is_inet6()) {
		init_sa6(&in.sa6, (in6_addr *)forwarder.addr, forwarder.port);
		sa = (sockaddr *)&in.sa6;
		salen = sizeof(in.sa6);
	} else {
		return false;
	}

	int sock = socket(upstream_proto.pfamily(), upstream_proto.socktype(), 0);
	if (sock == INVALID_SOCKET) {
		logprintf(LOG_DEFAULT, "socket: %s\n", strerror(errno));
		return false;
	}

	bool ok = false;

	if (connect(sock, sa, salen) == SOCKET_ERROR) {
		logprintf(LOG_DEFAULT, "connect: %s\n", strerror(errno));
	} else {
		dns::Message msg;
		msg.header.id = header.id;
		msg.header.flags = 0x0100;
		msg.questions = {question};

		InternalData d2 =*d;
		if (upstream_proto.is_inet4()) {
			d2.in4_tcp.fd = sock;
		} else if (upstream_proto.is_inet6()) {
			d2.in6_tcp.fd = sock;
		}
		if (send_dns_message(&d2, upstream_proto, msg, true, false)) {
			Task t;
			t.upstream_fd = sock;
			t.op = Operation::REPLY_TO_CLIENT_TCP;
			t.timestamp = misc::get_tick_count();
			t.local_transaction_id = local_transaction_id;
			t.requester_id = client_request_id;
			t.upstream_id = header.id;
			t.type = question.type;
			t.client_proto = client_proto;
			t.upstream_proto = upstream_proto;
			if (upstream_proto.is_inet4()) {
				t.client_sa4 = d->in4_udp.sa4;
			} else if (upstream_proto.is_inet6()) {
				t.client_sa6 = d->in6_udp.sa6;
			}
			t.request_name = question.name;
			t.forward_name = query_name;

			t.ev = {};
			t.ev.events = EPOLLIN;
			t.ev.data.fd = t.upstream_fd;
			push_task(t);

			ctl_add(t.upstream_fd, &t.ev);
			ok = true;
		}
	}

	return ok;
}

void Behind::process_query_udp(InternalData *d, ProtocolFamilyType const &client_proto, dns::Header const &header, dns::Question const &q)
{
	auto SendNXDOMAIN = [&](){
		dns::Message sending;
		sending.header.id = header.id;
		sending.header.flags = 0x8003;
		sending.questions = {q};
		send_dns_message(d, client_proto, sending, false, false);
	};

	auto SendNODATA = [&](){
		dns::Message sending;
		sending.header.id = header.id;
		sending.header.flags = 0x8000;
		sending.questions = {q};
		sending.authorities = {dns::Record()};
		dns::Record *r = &sending.authorities.back();
		r->name = q.name;
		r->type = DNS_TYPE::SOA;
		r->clas = q.clas;
		r->ttl = 60;
		r->set_soa(fake_soa());
		send_dns_message(d, client_proto, sending, false, false);
	};

	if (q.clas == DNS_CLASS_IN && !q.name.empty()) {
		if (!accept_dns_type(q.type)) {
			SendNODATA();
			return;
		}
		logprintf(LOG_DEFAULT, "Q: %s %s\n", q.name.c_str(), dns_type_to_string(q.type));
		// check known hosts
		InetResolver::Addr const *addr = m->hosts.find(q.name);
		if (addr) {
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
				sending.header.id = header.id;
				sending.header.flags = 0x8180;
				sending.questions = {q};
				sending.answers = rec;
				send_dns_message(d, client_proto, sending, false, false);
				return;
			}
			SendNXDOMAIN();
			return;
		}
		if (is_nxdomain(q.name)) {
			SendNXDOMAIN();
			return;
		}
		if (q.type == DNS_TYPE::AAAA && is_nodata_aaaa(q.name)) {
			SendNODATA();
			return;
		}
		dns::Cache *cache = get_cache(q.type);
		if (cache) {
			auto entry = cache->find(q.name);
			if (entry) {
				dns::Message sending;
				sending.header.id = header.id;
				sending.header.flags = 0x8180;
				sending.questions = {q};
				sending.answers = entry->answers;
				sending.authorities = entry->authorities;
				send_dns_message(d, client_proto, sending, false, true);
				return;
			}
		}

		const uint32_t local_transaction_id = next_local_transaction_id();
		clean_transaction(local_transaction_id);

		std::vector<Forwarder const *> forwarders = choose_forwarder(2);
		if (forwarders.empty()) {
			logprintf(LOG_DEFAULT, "No forwarder configured.\n");
			SendNODATA();
			return;
		}
		for (Forwarder const *f : forwarders) {
			forward_udp(*d, client_proto, header, q, local_transaction_id, *f);
		}
		return;
	}
}

void Behind::process_query_tcp(InternalData *d, ProtocolFamilyType const &client_proto, dns::Header const &header, dns::Question const &q)
{
	std::vector<Forwarder const *> forwarders = choose_forwarder(1);
	if (forwarders.empty()) {
		logprintf(LOG_DEFAULT, "No forwarder configured for TCP.\n");
		return;
	}

	const uint32_t local_transaction_id = next_local_transaction_id();
	Forwarder const *f = forwarders.front();
	if (!forward_tcp(d, client_proto, header.id, header, q, local_transaction_id, *f)) {
		logprintf(LOG_DEFAULT, "Failed to forward DNS query via TCP.\n");
	}
}

void Behind::reply_to_client_udp(InternalData *d, Task *task, dns::Message const &received)
{
	auto AmendName = [&task](std::string const &name){
		if (stricmp(task->request_name.c_str(), name.c_str()) == 0) {
			return task->request_name;
		} else {
			return misc::strtolower(name);
		}
	};
	if (received.questions.size() == 1 && received.questions.front().name == task->forward_name) {
		dns::Message sending;
		sending.header.id = task->requester_id;
		sending.header.flags = received.header.flags;
		// questions
		for (dns::Question const &q1 : received.questions) {
			dns::Question q2 = q1;
			q2.name = AmendName(q2.name);
			sending.questions.push_back(q2);
		}
		// answers
		for (dns::Record const &a1 : received.answers) {
			dns::Record a2 = a1;
			if (a2.clas == DNS_CLASS_IN) {
				if (accept_dns_type(a2.type)) {
					a2.name = AmendName(a2.name);
				}
				if (a2.type == DNS_TYPE::CNAME && a2.cname()) {
					a2.cname()->cname = AmendName(a2.cname()->cname);
				} else if (a2.type == DNS_TYPE::SOA && a2.soa()) {
					a2.soa()->nname = AmendName(a2.soa()->nname);
					a2.soa()->rname = AmendName(a2.soa()->rname);
				}
				sending.answers.push_back(a2);
			}
		}
		// send
		auto d2 = *d;
		d2.in4_udp.sa4 = task->client_sa4;
		d2.in6_udp.sa6 = task->client_sa6;
		send_dns_message(&d2, task->client_proto, sending, false, false);
		// cahce
		dns::Cache *cache = get_cache(task->type);
		if (cache) {
			cache->insert(task->forward_name, sending);
		}
	}
}

void Behind::process_response(InternalData *d, ProtocolFamilyType const &upstream_proto, dns::Message const &received)
{
	auto opt = take_task_by_id(received.header.id);
	if (!opt) return;
	Task *task = &*opt;
	if (task->upstream_proto == upstream_proto && accept_dns_type(task->type)) {
		bool tc = bool(received.header.flags & 0x0200);
		if (tc) { // truncated
			std::vector<Forwarder const *> forwarders = choose_forwarder(1);
			if (!forwarders.empty()) {
				dns::Header header;
				header.id = next_txid();
				header.flags = received.header.flags & ~0x0200;
				dns::Question q;
				if (!received.questions.empty()) {
					q = received.questions.front();
				}
				auto local_transaction_id = next_local_transaction_id();
				forward_tcp(d, task->client_proto, task->requester_id, header, q, local_transaction_id, *forwarders.front());
			}
		} else {
			if (task->op == Operation::REPLY_TO_CLIENT_UDP) {
				reply_to_client_udp(d, task, received);
			}
		}
	}
}

bool Behind::process_receive(InternalData *d, int fd)
{
	auto opt = take_task_by_fd(fd);
	if (!opt) return false;
	Task *task = &*opt;
	if (task->op == Operation::REPLY_TO_CLIENT_TCP) {
		char buf[4096];
		int n = recv(task->upstream_fd, buf, sizeof(buf), 0);
		if (n > 2) {
			n -= 2;
			n = std::min(n, (int)ntohs(*(uint16_t *)buf));
			char const *begin = buf + 2;
			char const *end = begin + n;
			dns::Message msg;
			parse_dns_message(begin, end, &msg);
			msg.header.id = task->requester_id;
			send_dns_message(d, task->client_proto, msg, false, false);
		}
		ctl_del(task->upstream_fd, &task->ev);
		closesocket(task->upstream_fd);
		return true;
	} else if (task->op == Operation::REPLY_TO_CLIENT_UDP) {
		char buf[4096];
		int n = recv(fd, buf, sizeof(buf), 0);
		if (n > 0) {
			dns::Message received;
			parse_dns_message(buf, buf + n, &received);
			reply_to_client_udp(d, task, received);
		}
		ctl_del(task->upstream_fd, &task->ev);
		closesocket(task->upstream_fd);
		return true;
	}
	return false;
}

void Behind::process(InternalData *d, ProtocolFamilyType const &client_proto)
{
	if (client_proto.is_inet4() || client_proto.is_inet6()) {
		std::vector<char> buf;
		buf = read(d, client_proto);
		if (buf.size() < 12) return;

		dns::Message received;
		parse_dns_message(buf.data(), buf.data() + buf.size(), &received);

		if ((received.header.flags & 0xf800) == 0x0000) { // standard query
			for (auto it = received.questions.begin(); it != received.questions.end(); it++) {
				dns::Question const &q = *it;
				if (client_proto.is_dgram()) {
					process_query_udp(d, client_proto, received.header, q);
				} else if (client_proto.is_stream()) { // experimental
					process_query_tcp(d, client_proto, received.header, q);
				}
			}
		} else if (received.header.flags & 0x8000) { // response
			process_response(d, client_proto, received);
		}
	}
}

void Behind::process_udp(InternalData *d, sa_family_t family, int fd)
{
	process(d, {family, SOCK_DGRAM});
}

void Behind::process_tcp(InternalData *d, sa_family_t family)
{
	if (family == AF_INET) {
		socklen_t len = sizeof(d->in4_tcp.sa4);
		d->in4_tcp.fd = accept(d->in4_tcp.listener_fd, (sockaddr *)&d->in4_tcp.sa4, &len);
		process(d, {family, SOCK_STREAM});
	} else if (family = AF_INET6) {
		socklen_t len = sizeof(d->in6_tcp.sa6);
		d->in6_tcp.fd = accept(d->in6_tcp.listener_fd, (sockaddr *)&d->in6_tcp.sa6, &len);
		process(d, {family, SOCK_STREAM});
	}
}

bool Behind::bind(void *private_in, ProtocolFamilyType const &proto, int sock)
{
	Behind::InternalData::In *in = static_cast<Behind::InternalData::In *>(private_in);
	int r;
	if (proto.is_inet4()) {
		init_sa4(&in->sa4, nullptr, listen_port());
		r = ::bind(sock, (struct sockaddr *)&in->sa4, sizeof(in->sa4));
	} else {
		init_sa6((sockaddr_in6 *)&in->sa6, nullptr, listen_port());
		r = ::bind(sock, (struct sockaddr *)&in->sa6, sizeof(in->sa6));
	}
	if (r == SOCKET_ERROR) return false;
	return true;
}

void Behind::init_socket(void *private_in, ProtocolFamilyType proto)
{
	Behind::InternalData::In *in = static_cast<Behind::InternalData::In *>(private_in);

	int sock = socket(proto.pfamily(), proto.socktype(), 0);
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

	if (!bind(in, proto, sock)) {
		throw STRERROR("bind: ");
	}

	if (proto.is_dgram()) {
		in->fd = sock;
	} else if (proto.is_stream()) {
		if (listen(sock, 5) == SOCKET_ERROR) {
			throw STRERROR("listen: ");
		}
		in->listener_fd = sock;
	}

	InetResolver::Addr addr;
	if (proto.is_inet4()) {
		addr.add_in4(&in->sa4.sin_addr.s_addr);
	} else if (proto.is_inet6()) {
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

int ev_fd(struct epoll_event *e)
{
	return e->data.fd;
}

int Behind::ctl_add(int fd, struct epoll_event *e)
{
	m->poll_fds.push_back(fd);

	int ret = 0;
	if (e && m->epoll_fd != -1) {
		ret = epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, e->data.fd, e);
	}
	return ret;
}

int Behind::ctl_del(int fd, struct epoll_event *e)
{
	auto it = std::remove(m->poll_fds.begin(), m->poll_fds.end(), fd);
	m->poll_fds.erase(it, m->poll_fds.end());

	int ret = 0;
	if (e && m->epoll_fd != -1) {
		ret = epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, e->data.fd, e);
	}
	return ret;
}

int Behind::ctl_del(int fd)
{
	return ctl_del(fd, nullptr);
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

		ctl_add(d.in4_udp.fd, nullptr);
		ctl_add(d.in6_udp.fd, nullptr);
		ctl_add(d.in4_tcp.listener_fd, nullptr);
		ctl_add(d.in6_tcp.listener_fd, nullptr);

		while (1) {
			fd_set fds;
			FD_ZERO(&fds);
			int maxfd = -1;
			for (int fd : m->poll_fds) {
				FD_SET(fd, &fds);
				maxfd = std::max(maxfd, fd);
			}
			select(maxfd + 1, &fds, nullptr, nullptr, nullptr);

			int fd;
			fd = d.in4_udp.fd;
			if (FD_ISSET(fd, &fds)) {
				process_udp(&d, AF_INET, fd);
				FD_CLR(fd, &fds);
			}
			fd = d.in6_udp.fd;
			if (FD_ISSET(fd, &fds)) {
				process_udp(&d, AF_INET6, fd);
				FD_CLR(fd, &fds);
			}
			fd = d.in4_tcp.listener_fd;
			if (FD_ISSET(fd, &fds)) {
				process_tcp(&d, AF_INET);
				FD_CLR(fd, &fds);
			}
			fd = d.in6_tcp.listener_fd;
			if (FD_ISSET(fd, &fds)) {
				process_tcp(&d, AF_INET6);
				FD_CLR(fd, &fds);
			}
			for (int fd : m->poll_fds) {
				if (FD_ISSET(fd, &fds)) {
					process_receive(&d, fd);
					FD_CLR(fd, &fds);
				}
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
				in->ev.data.fd = in->fd;
			} else if (socktype == SOCK_STREAM) {
				in->ev.data.fd = in->listener_fd;
			}
			if (ctl_add(in->fd, &in->ev) == -1) {
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
				if (fd == d.in4_udp.fd) {
					process_udp(&d, AF_INET, fd);
				} else if (fd == d.in6_udp.fd) {
					process_udp(&d, AF_INET6, fd);
				} else if (fd == d.in4_tcp.listener_fd) {
					process_tcp(&d, AF_INET);
				} else if (fd == d.in6_tcp.listener_fd) {
					process_tcp(&d, AF_INET6);
				} else {
					if (!process_receive(&d, fd)) {
						ctl_del(fd);
						closesocket(fd);
					}
				}
			}
			clean();
		}
	}

	for (int fd : m->poll_fds) {
		closesocket(fd);
	}
	m->poll_fds.clear();

	closesocket(d.in4_udp.fd);
	closesocket(d.in6_udp.fd);
	closesocket(d.in4_udp.listener_fd);
	closesocket(d.in6_udp.listener_fd);
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

