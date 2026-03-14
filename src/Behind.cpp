#include "Behind.h"
#include "LineReader.h"
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
#include <mutex>
#include <thread>
#include <unistd.h>
#include <sys/stat.h>

#define stricmp(A, B) strcasecmp(A, B)
#define STRERROR(S) (std::string(S) + strerror(errno))
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket(S) close(S)

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
	DNS_TYPE type = DNS_TYPE::A;
	DNS_CLASS clas = DNS_CLASS::IN;
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

struct HTTPS {
	uint16_t priority;
	std::string name;
	std::vector<char> data;
};

struct Record {
	std::string name;
	DNS_TYPE type = DNS_TYPE::A;
	DNS_CLASS clas = DNS_CLASS::IN;
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
	
	// https
	
	void set_https(std::shared_ptr<HTTPS> https)
	{
		sp = https;
	}
	HTTPS *https()
	{
		if (type == DNS_TYPE::HTTPS && sp) {
			return std::static_pointer_cast<HTTPS>(sp).get();
		}
		return nullptr;
	}
	HTTPS const *https() const
	{
		return const_cast<Record *>(this)->https();
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
	std::vector<Record> additionals;
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
	void insert(std::string const &name, Message const &msg, int cache_min_ttl)
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
			uint32_t ttl =std::max(item->answers[i].ttl, (uint32_t)cache_min_ttl);
			item->answers[i].expire = now + ttl * 1000;
			item->expire = std::min(item->expire, item->answers[i].expire);
		}
	}
};

} // namespace dns

struct Behind::Task {
	Behind::Operation op = Operation::NONE;
	bool connect_in_progress = false;
	std::shared_ptr<Behind::ForwardingThreadData> fwdata;
	uint64_t timestamp = 0;
	int timeout = 1000;
	uint32_t local_transaction_id = 0;
	uint16_t upstream_id = 0;
	uint16_t requester_id = 0;
	DNS_TYPE type = DNS_TYPE::A;
	ProtocolFamilyType client_proto;
	ProtocolFamilyType upstream_proto;
	int upstream_fd = -1;
	std::vector<char> buffer;
	std::shared_ptr<epoll_event> ev = std::make_shared<epoll_event>();
	union {
		sockaddr_in client_sa4;
		sockaddr_in6 client_sa6;
	};
	std::string request_name;
	std::string forward_name;
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
	In in4_tcp, in6_tcp;
};

struct Behind::ForwardingThreadData {
	Behind::InternalData d;
	Forwarder forwarder;
	dns::Message msg;
};

struct Behind::Private {
	Option option;

	uint64_t start_time = 0;
	uint64_t last_uptime_min = 0;

	std::vector<Hosts> hosts;
	uint32_t local_transaction_id = 0;
	TransactionIdGenerator txid_gen;
	InetResolver resolver;
	
	Behind::SocketMode socket_mode;
	fd_set readfds;
	int epoll_fd = -1;
	std::vector<int> select_in_fds;
	std::vector<int> select_out_fds;
	std::vector<epoll_event> epoll_events{100};
	
	struct {
		dns::Cache a;
		dns::Cache aaaa;
		dns::Cache soa;
		dns::Cache txt;
		dns::Cache https;
	} dns_cache;
	std::vector<std::shared_ptr<Behind::Task>> tasks;
	std::vector<Forwarder> forwarders;
};

const InetResolver::Addr *Hosts::find(const std::string &name) const
{
	std::string key = misc::strtolower(name);
	auto it = map_.find(key);
	if (it != map_.end()) {
		return &it->second;
	}
	return nullptr;
}

void Hosts::set(const std::string &name, const InetResolver::Addr &addr)
{
	map_[misc::strtolower(name)] = addr;
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

int Behind::decode_name(const char *begin, const char *end, const char *ptr, std::string *name)
{
	name->clear();
	if (begin && end && ptr && begin <= ptr && ptr < end) {
		char buf[253];
		size_t len = 0;
		char const *start = ptr;
		char const *lower = ptr;
		char const *upper = end;
		char const *firstjump = nullptr;
		while (ptr < upper) {
			uint8_t n(*ptr);
			uint8_t bits = n & 0xc0;
			if (bits == 0xc0) {
				if (ptr + 1 < upper) {
					int offset = ((n & 0x3f) << 8) | (ptr[1] & 0xff);
					char const *next = begin + offset;
					if (next < lower) {
						if (!firstjump) {
							firstjump = ptr + 2;
						}
						upper = lower;
						lower = next;
						ptr = next;
						continue;
					}
				}
				break;
			}
			if (bits != 0x00) {
				break;
			}
			ptr++;
			if (n == 0) { // normal end
				name->assign(buf, len);
				return (firstjump ? firstjump : ptr) - start;
			}
			if (len + 1 + n > sizeof(buf)) {
				break;
			}
			if (len > 0) {
				buf[len++] = '.';
			}
			memcpy(buf + len, ptr, n);
			len += n;
			ptr += n;
		}
	}
	return 0;
}

void Behind::write_dns_header(std::vector<char> *out, dns::Header const &h)
{
	uint16_t tmp[6];
	tmp[0] = htons(h.id);
	tmp[1] = htons(h.flags);
	tmp[2] = htons(h.qdcount);
	tmp[3] = htons(h.ancount);
	tmp[4] = htons(h.nscount);
	tmp[5] = htons(h.arcount);
	write(out, (char const *)tmp, 12);
}

void Behind::write_dns_question_rr(std::vector<char> *out, NameMap *namemap, const std::string &name, DNS_TYPE type, DNS_CLASS clas)
{
	write_name(out, namemap, name);
	write_us(out, (uint16_t)type);
	write_us(out, (uint16_t)clas);
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

bool Behind::write_dns_answer_rr(std::vector<char> *out, NameMap *namemap, std::string const &name, const dns::Record &item)
{
	write_name(out, namemap, name);
	write_us(out, (int)item.type);
	write_us(out, (int)item.clas);
	write_ul(out, item.ttl);
	
	size_t i = out->size();
	write_us(out, 0);
	if (item.type == DNS_TYPE::CNAME) {
		dns::CNAME const *cname = item.cname();
		if (!cname) return false;
		write_name(out, namemap, cname->cname);
	} else if (item.type == DNS_TYPE::NS) {
		dns::NS const *ns = item.ns();
		if (!ns) return false;
		write_name(out, namemap, ns->nsname);
	} else if (item.type == DNS_TYPE::MX) {
		dns::MX const *mx = item.mx();
		if (!mx) return false;
		write_us(out, mx->preference);
		write_name(out, namemap, mx->exchange);
	} else if (item.type == DNS_TYPE::SOA) {
		auto WriteSOA = [&](dns::SOA const &soa){
			write_name(out, namemap, soa.nname);
			write_name(out, namemap, soa.rname);
			write_ul(out, soa.serial);
			write_ul(out, soa.refresh);
			write_ul(out, soa.retry);
			write_ul(out, soa.expire);
			write_ul(out, soa.minimum);
		};
		if (item.soa()) {
			WriteSOA(*item.soa());
		}
	} else if (item.type == DNS_TYPE::HTTPS) {
		dns::HTTPS const *https = item.https();
		if (!https) return false;
		write_us(out, https->priority);
		write_name(out, namemap, https->name);
		if (!https->data.empty()) {
			write(out, https->data.data(), https->data.size());
		}
	} else {
		int len = item.bin.size();
		if (item.type == DNS_TYPE::A && len == 4) {
			// len = 4;
		} else if (item.type == DNS_TYPE::AAAA && len == 16) {
			// len = 16;
		} else if (item.type == DNS_TYPE::OPT) {
			// through
		} else if (item.type == DNS_TYPE::TXT) {
			// through
		} else {
			return false;
		}
		write(out, (char const *)item.bin.data(), len);
	}
	write_us(&out->at(i), out->size() - i - 2);
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
		out->clas = (DNS_CLASS)ntohs(tmp[1]);
		return ptr - start;
	}
	return 0;
}

std::vector<Forwarder const *> Behind::choose_forwarder(std::string const &name, size_t max) const
{
	std::vector<Forwarder const *> default_forwarders;
	std::vector<Forwarder const *> matched_forwarders;

	for (Forwarder const &f : m->forwarders) {
		if (f) {
			assert(!f.zone.empty() && f.zone.back() == '.');
			size_t n = f.zone.size();
			if (n == 1) {
				default_forwarders.push_back(&f);
			} else if (n > 1) {
				n--;
				size_t i = name.size();
				if (i >= n) {
					i -= n;
					if (i == 0 || name[i - 1] == '.') {
						auto Compare = [&](){
							for (size_t j = 0; j < n; j++) {
								if (tolower((unsigned char)name[i + j]) != tolower((unsigned char)f.zone[j])) {
									return false;
								}
							}
							return true;
						};
						if (Compare()) {
							matched_forwarders.push_back(&f);
						}
					}
				}
			}
		}
	}

	std::vector<Forwarder const *> *forwarders = matched_forwarders.empty() ? &default_forwarders : &matched_forwarders;

	{ // shuffle and resize
		size_t n = forwarders->size();
		size_t m = std::min((size_t)max, n);
		for (size_t i = 0; i < m; i++) {
			size_t j = i + rand() % (n - i);
			std::swap(forwarders->at(i), forwarders->at(j));
		}
		forwarders->resize(m);
	}

	return *forwarders;
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

InetAddrPort InetAddrPort::parse(std::string name)
{
	InetAddrPort ret;

	std::regex re_ipv4(R"(^\s*((\d{1,3}\.){3}\d{1,3})(@(\d+))?\s*$)");
	std::regex re_ipv6(R"(^\s*(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+)(@(\d+))?\s*$)");

	if (std::smatch m; std::regex_match(name, m, re_ipv4)) {
		name = m[1];
		if (m[4].matched) {
			ret.port = std::stoi(m[4]);
		}
		ret.addr.type = InetResolver::IN4;
		struct sockaddr_in sa4 = {};
		inet_pton(AF_INET, name.c_str(), &sa4.sin_addr);
		ret.addr.add_in4(&sa4.sin_addr.s_addr);
	} else if (std::smatch m; std::regex_match(name, m, re_ipv6)) {
		name = m[1];
		if (name.front() == '[' && name.back() == ']') {
			name = name.substr(1, name.size() - 2);
		}
		if (m[3].matched) {
			ret.port = std::stoi(m[3]);
		}
		ret.addr.type = InetResolver::IN6;
		struct sockaddr_in6 sa6 = {};
		inet_pton(AF_INET6, name.c_str(), &sa6.sin6_addr);
		ret.addr.add_in6(&sa6.sin6_addr.s6_addr);
	}
	return ret;
}

void Behind::init_forwarder()
{
	for (Option::Zone const &z : m->option.forward_addr) {
		InetResolver::Addr addr;
		int port = STANDARD_DNS_PORT;
		
		auto addrport = InetAddrPort::parse(z.name);
		InetResolver::Type type = addrport.addr.type;

		m->resolver.resolve(z.name.c_str(), type, &addr);
		
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
		
		assert(!z.zone.empty() && z.zone.back() == '.');
		forwarder.zone = z.zone;
		m->forwarders.push_back(forwarder);
	}
}

int Behind::ctl_add(int fd, struct epoll_event *e, bool in, bool out)
{
	if (fd == -1) return -1;
	int ret = 0;

	auto Add = [](std::vector<int> *fds, int fd){
		fds->push_back(fd);
	};
	if (in)  Add(&m->select_in_fds, fd);
	if (out) Add(&m->select_out_fds, fd);
	logprintf(LOG_DEFAULT, "(debug) fd tracking: add %d, in=%d, out=%d\n", fd, (int)m->select_in_fds.size(), (int)m->select_out_fds.size());
	
	if (e && m->epoll_fd != -1) {
		ret = epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, e->data.fd, e);
	}
	return ret;
}

int Behind::ctl_del(int fd, struct epoll_event *e)
{
	if (fd == -1) return -1;
	int ret = 0;

	auto Remove = [](std::vector<int> *fds, int fd){
		auto it = std::remove(fds->begin(), fds->end(), fd);
		fds->erase(it, fds->end());
	};
	Remove(&m->select_in_fds, fd);
	Remove(&m->select_out_fds, fd);
	logprintf(LOG_DEFAULT, "(debug) fd tracking: del %d, in=%d, out=%d\n", fd, (int)m->select_in_fds.size(), (int)m->select_out_fds.size());
	
	if (e && m->epoll_fd != -1) {
		ret = epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, e->data.fd, e);
	}
	return ret;
}

void Behind::delete_socket(int fd, struct epoll_event *e)
{
	ctl_del(fd, e);
	closesocket(fd);
}

void Behind::delete_socket(std::shared_ptr<Task> task)
{
	if (task) {
		delete_socket(task->upstream_fd, task->ev.get());
	}
}

void Behind::uptime()
{
	uint64_t now = misc::get_tick_count();
	uint64_t uptime_ms = now - m->start_time;
	uint64_t uptime_sec = uptime_ms / 1000;
	uint64_t uptime_min = uptime_sec / 60;

	if (uptime_min != m->last_uptime_min) {
		m->last_uptime_min = uptime_min;
		int days = int(uptime_min / (60 * 24));
		int minutes = int(uptime_min % (60 * 24));
		int hours = minutes / 60;
		minutes %= 60;
		logprintf(LOG_DEFAULT, "(info) uptime: %d days %d:%02d\n", days, hours, minutes);
	}
}

void Behind::clean()
{
	uint64_t now = misc::get_tick_count();
	size_t i = m->tasks.size();
	while (i > 0) {
		i--;
		if (now - m->tasks[i]->timestamp >= m->tasks[i]->timeout) {
			delete_socket(m->tasks[i]);
			m->tasks.erase(m->tasks.begin() + i);
		}
	}
}

void Behind::clean_transaction(uint32_t id)
{
	size_t i = m->tasks.size();
	while (i > 0) {
		i--;
		if (id == m->tasks[i]->local_transaction_id) {
			delete_socket(m->tasks[i]);
			m->tasks.erase(m->tasks.begin() + i);
		}
	}
}

std::shared_ptr<Behind::Task> Behind::take_task_item(std::vector<std::shared_ptr<Behind::Task>> *tasks, size_t index)
{
	std::shared_ptr<Behind::Task> item = std::move(tasks->at(index));
	std::swap(tasks->at(index), tasks->back());
	tasks->pop_back();
	clean_transaction(item->local_transaction_id);
	return item;
}

std::shared_ptr<Behind::Task> Behind::take_task_by_id(uint16_t upstream_id)
{
	for (size_t i = 0; i < m->tasks.size(); i++) {
		if (m->tasks[i]->upstream_id == upstream_id) {
			return take_task_item(&m->tasks, i);
		}
	}
	return {};
}

std::shared_ptr<Behind::Task> Behind::take_task_by_fd(int fd)
{
	for (size_t i = 0; i < m->tasks.size(); i++) {
		if (m->tasks[i]->upstream_fd == fd) {
			return take_task_item(&m->tasks, i);
		}
	}
	return {};
}

void Behind::push_task(std::shared_ptr<Task> task, int timeout, uint32_t epoll_events)
{
	{
		auto t = take_task_by_id(task->upstream_id);
		delete_socket(t);
	}

	init_epoll_event(task.get(), task->upstream_fd, epoll_events);
	ctl_add(task->upstream_fd, task->ev.get(), true, false);

	task->timestamp = misc::get_tick_count();
	task->timeout = timeout;

	m->tasks.push_back(task);
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
				a.clas = (DNS_CLASS)ntohs(tmp[1]);
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
					} else if (a.type == DNS_TYPE::HTTPS) {
						if (rdlen > 2) {
							std::shared_ptr<dns::HTTPS> https = std::make_shared<dns::HTTPS>();
							https->priority = ntohs(*(uint16_t *)ptr);
							ptr += 2;
							int n = decode_name(begin, end, ptr, &https->name);
							if (n > 0) {
								https->name = misc::strtolower(https->name);
								ptr += n;
							}
							if (n < rdlen) {
								n = rdlen - 2 - n;
								https->data.resize(n);
								memcpy(https->data.data(), ptr, n);
							}
							it->set_https(https);
							ptr += rdlen;
						}
					} else if (a.type == DNS_TYPE::TXT) {
						if (rdlen > 0) {
							it->bin.resize(rdlen);
							memcpy(it->bin.data(), ptr, rdlen);
							ptr += rdlen;
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

std::pair<int, std::string> sock_and_address(Behind::InternalData *d, ProtocolFamilyType const &proto)
{
	if (proto.is_dgram()) {
		if (proto.is_inet4()) {
			return {d->in4_udp.fd, ::addr_to_string(AF_INET, (struct sockaddr *)&d->in4_udp.sa4)};
		} else if (proto.is_inet6()) {
			return {d->in6_udp.fd, ::addr_to_string(AF_INET6, (struct sockaddr *)&d->in6_udp.sa6)};
		}
	} else if (proto.is_stream()) {
		if (proto.is_inet4()) {
			return {d->in4_tcp.fd, ::addr_to_string(AF_INET, (struct sockaddr *)&d->in4_tcp.sa4)};
		} else if (proto.is_inet6()) {
			return {d->in6_tcp.fd, ::addr_to_string(AF_INET6, (struct sockaddr *)&d->in6_tcp.sa6)};
		}
	}
	return {-1, {}};
	
}

struct Sender {
	int sock = -1;
	ProtocolFamilyType proto;
	Sender(ProtocolFamilyType const &proto)
		: proto(proto)
	{
	}
	ssize_t send(Behind::InternalData *d, void const *buf, size_t len)
	{
		int flags = 0;
		auto [sock, addr_str] = sock_and_address(d, proto);
		(void)addr_str;
		if (sock != -1) {
			if (proto.is_dgram()) {
				if (proto.is_inet4()) {
					return ::sendto(sock, buf, len, flags, (struct sockaddr *)&d->in4_udp.sa4, sizeof(sockaddr_in));
				} else if (proto.is_inet6()) {
					return ::sendto(sock, buf, len, flags, (struct sockaddr *)&d->in6_udp.sa6, sizeof(sockaddr_in6));
				}
			} else if (proto.is_stream()) {
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
	case DNS_TYPE::TXT:
		return "TXT";
	case DNS_TYPE::AAAA:
		return "AAAA";
	case DNS_TYPE::HTTPS:
		return "HTTPS";
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

Behind::Packet Behind::make_dns_packet(dns::Message const &msg, bool tcp)
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
	h.arcount = LimitCount(msg.additionals.size());
	
	write_dns_header(&ret.buffer, h);
	
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
		if (!write_dns_answer_rr(&ret.buffer, &namemap, name, r)) {
			return {};
		}
	}
	
	for (int i = 0; i < h.nscount; i++) {
		dns::Record const &r = msg.authorities[i];
		std::string name = stricmp(ret.q.name.c_str(), r.name.c_str()) == 0 ? ret.q.name : misc::strtolower(r.name);
		if (!write_dns_answer_rr(&ret.buffer, &namemap, name, r)) {
			return {};
		}
	}
	
	for (int i = 0; i < h.arcount; i++) {
		dns::Record const &r = msg.additionals[i];
		std::string name;
		if (0) {
			name = stricmp(ret.q.name.c_str(), r.name.c_str()) == 0 ? ret.q.name : misc::strtolower(r.name);
		}
		if (!write_dns_answer_rr(&ret.buffer, &namemap, name, r)) {
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
	Packet packet = make_dns_packet(msg, tcp);
	if (!packet) return false;
	
	Sender sender(proto);
	bool ok = sender.send(d, &packet.buffer[0], packet.buffer.size()) == (ssize_t)packet.buffer.size();
	
	auto [sock, client] = sock_and_address(d, proto);
	(void)sock;
	
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



InetResolver::Addr const *Behind::find_host(std::string const &name)
{
	update_hosts_files(false);

	for (Hosts const &hosts : m->hosts) {
		InetResolver::Addr const *ret = hosts.find(name);
		if (ret) return ret;
	}
	return nullptr;
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
	case DNS_TYPE::A:     return &m->dns_cache.a;
	case DNS_TYPE::AAAA:  return &m->dns_cache.aaaa;
	case DNS_TYPE::SOA:   return &m->dns_cache.soa;
	case DNS_TYPE::TXT:   return &m->dns_cache.txt;
	case DNS_TYPE::HTTPS: return &m->dns_cache.https;
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
	case DNS_TYPE::TXT:
	case DNS_TYPE::HTTPS:
	case DNS_TYPE::OPT:
		return true;
	}
	return false;
}

std::shared_ptr<Behind::Task> Behind::make_task(Operation op, uint32_t local_transaction_id)
{
	std::shared_ptr<Task> t = std::make_shared<Task>();
	t->local_transaction_id = local_transaction_id;
	t->op = op;
	return t;
}

void Behind::init_epoll_event(Behind::Task *task, int fd, uint32_t events)
{
	*task->ev = {};
	task->ev->events = events;
	task->ev->data.fd = fd;
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
		sock = socket(forwarder.af_type, SOCK_DGRAM, 0);
		if (sock == INVALID_SOCKET) {
			throw STRERROR("socket: ");
		}
		
		fcntl(sock, F_SETFL, O_NONBLOCK);
		
		{
			int yes = 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
			if (forwarder.is_inet6()) {
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
		std::shared_ptr<Task> t = make_task(Operation::REPLY_TO_CLIENT_UDP, local_transaction_id);
		t->upstream_fd = sock;
		t->requester_id = header.id;
		t->upstream_id = sending.header.id;
		t->type = question.type;
		t->client_proto = client_proto;
		t->upstream_proto = {forwarder.af_type, SOCK_DGRAM};
		if (client_proto.is_inet4()) {
			t->client_sa4 = d.in4_udp.sa4;
		} else if (client_proto.is_inet6()) {
			t->client_sa6 = d.in6_udp.sa6;
		}
		t->request_name = question.name;
		t->forward_name = query_name;
		push_task(t, 1000, EPOLLIN | EPOLLERR | EPOLLHUP);
	} else {
		closesocket(sock);
	}
}

void Behind::forward_tcp(InternalData *d, ProtocolFamilyType const &client_proto, uint16_t client_request_id, dns::Header const &header, dns::Question const &question, uint32_t local_transaction_id, Forwarder const &forwarder)
{
	std::shared_ptr<Task> task = make_task(Operation::FORWARD_TO_UPSTREAM_TCP, local_transaction_id);

	task->fwdata = std::make_shared<ForwardingThreadData>();
	task->fwdata->d = *d;
	task->fwdata->forwarder = forwarder;
	
	task->fwdata->msg.header.id = header.id;
	task->fwdata->msg.header.flags = 0x0100;
	task->fwdata->msg.questions = {question};
	
	if (task->fwdata->forwarder.is_inet4()) {
		task->client_sa4 = d->in4_udp.sa4;
	} else if (task->fwdata->forwarder.is_inet6()) {
		task->client_sa6 = d->in6_udp.sa6;
	} else {
		return;
	}
	
	task->requester_id = client_request_id;
	task->upstream_id = header.id;
	task->request_name = question.name;
	task->forward_name = m->option.case_randomize ? randomize_case(question.name) : question.name;
	task->type = question.type;
	task->client_proto = client_proto;
	
	int sock = socket(task->fwdata->forwarder.af_type, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		logprintf(LOG_DEFAULT, "socket: %s\n", strerror(errno));
		return;
	}
	fcntl(sock, F_SETFL, O_NONBLOCK);
	
	ProtocolFamilyType upstream_proto = {task->fwdata->forwarder.af_type, SOCK_STREAM};
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	sockaddr *sa = nullptr;
	socklen_t salen = 0;
	if (upstream_proto.is_inet4()) {
		task->fwdata->d.in4_tcp.fd = sock;
		init_sa4(&sa4, (in_addr *)task->fwdata->forwarder.addr, task->fwdata->forwarder.port);
		sa = (sockaddr *)&sa4;
		salen = sizeof(sa4);
	} else if (upstream_proto.is_inet6()) {
		task->fwdata->d.in6_tcp.fd = sock;
		init_sa6(&sa6, (in6_addr *)task->fwdata->forwarder.addr, task->fwdata->forwarder.port);
		sa = (sockaddr *)&sa6;
		salen = sizeof(sa6);
	}

	bool done = false;
	if (sa) {
		auto e = connect(sock, sa, salen);
		if (e < 0) {
			if (errno == EINPROGRESS) {
				task->connect_in_progress = true;
				task->upstream_proto = upstream_proto;
				task->upstream_fd = sock;
				push_task(task, 1000, EPOLLOUT | EPOLLERR | EPOLLHUP);
				done = true;
			} else {
				logprintf(LOG_DEFAULT, "connect: %s\n", strerror(errno));
			}
		}
	}
	if (!done) {
		closesocket(sock);
	}
}

void Behind::set_edns0(dns::Message *msg)
{
	size_t i = msg->additionals.size();
	while (i > 0) {
		i--;
		if (msg->additionals[i].type == DNS_TYPE::OPT) {
			msg->additionals.erase(msg->additionals.begin() + i);
		}
	}
	
	const uint16_t payload_size = 1232;
	const uint8_t ex_rcode = 0;
	const uint8_t version = 0;
	const bool dnssec_ok = false;
	const uint16_t z = 0;
	
	dns::Record edns0;
	edns0.type = DNS_TYPE::OPT;
	edns0.clas = (DNS_CLASS)payload_size;
	edns0.ttl = ((uint32_t)ex_rcode << 24) | ((uint32_t)version << 16) | (dnssec_ok ? 0x8000 : 0) | z;
	msg->additionals.push_back(edns0);
}

bool Behind::reply_from_cache(InternalData *d, ProtocolFamilyType const &client_proto, dns::Header const &header, dns::Question const &q)
{
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
			set_edns0(&sending);
			send_dns_message(d, client_proto, sending, false, true);
			return true;
		}
	}
	return false;
}

void Behind::process_query_udp(InternalData *d, ProtocolFamilyType const &client_proto, dns::Message const &received, dns::Question const &q)
{
	auto SendNXDOMAIN = [&](){
		dns::Message sending;
		sending.header.id = received.header.id;
		sending.header.flags = 0x8003;
		sending.questions = {q};
		send_dns_message(d, client_proto, sending, false, false);
	};
	
	auto SendNODATA = [&](){
		dns::Message sending;
		sending.header.id = received.header.id;
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
	
	if (q.clas == DNS_CLASS::IN && !q.name.empty()) {
		if (!accept_dns_type(q.type)) {
			SendNODATA();
			return;
		}
		logprintf(LOG_DEFAULT, "Q: %s %s\n", q.name.c_str(), dns_type_to_string(q.type));
		// check known hosts
		InetResolver::Addr const *addr = find_host(q.name);
		if (addr) {
			std::vector<dns::Record> rec;
			if ((q.type == DNS_TYPE::A && addr->type == InetResolver::IN4) || (q.type == DNS_TYPE::AAAA && addr->type == InetResolver::IN6)) {
				dns::Record r;
				r.name = q.name;
				r.type = q.type;
				r.ttl = cache_min_ttl();
				for (std::vector<uint8_t> const &a : addr->addr) {
					r.bin = a;
					rec.push_back(r);
				}
				dns::Message sending;
				sending.header.id = received.header.id;
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
		
		if (reply_from_cache(d, client_proto, received.header, q)) {
			return;
		}
		
		const uint32_t local_transaction_id = next_local_transaction_id();
		clean_transaction(local_transaction_id);
		
		std::vector<Forwarder const *> forwarders = choose_forwarder(q.name, 2);
		if (forwarders.empty()) {
			logprintf(LOG_DEFAULT, "No forwarder configured.\n");
			SendNODATA();
			return;
		}
		for (Forwarder const *f : forwarders) {
			forward_udp(*d, client_proto, received.header, q, local_transaction_id, *f);
		}
		return;
	}
}

void Behind::process_query_tcp(InternalData *d, ProtocolFamilyType const &client_proto, dns::Message const &received, dns::Question const &q)
{
	std::vector<Forwarder const *> forwarders = choose_forwarder(q.name, 1);
	if (forwarders.empty()) {
		logprintf(LOG_DEFAULT, "No forwarder configured for TCP.\n");
		return;
	}
	
	if (reply_from_cache(d, client_proto, received.header, q)) {
		return;
	}
	
	const uint32_t local_transaction_id = next_local_transaction_id();
	Forwarder const *f = forwarders.front();
	forward_tcp(d, client_proto, received.header.id, received.header, q, local_transaction_id, *f);
}

void Behind::reply_to_client_udp(InternalData *d, std::shared_ptr<Task> task, dns::Message const &received)
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
		if (received.answers.empty()) {
			sending.authorities = received.authorities;
		} else {
			for (dns::Record const &a1 : received.answers) {
				dns::Record a2 = a1;
				if (a2.clas == DNS_CLASS::IN) {
					if (accept_dns_type(a2.type)) {
						a2.name = AmendName(a2.name);
					}
					if (a2.type == DNS_TYPE::CNAME && a2.cname()) {
						a2.cname()->cname = AmendName(a2.cname()->cname);
					} else if (a2.type == DNS_TYPE::SOA && a2.soa()) {
						a2.soa()->nname = AmendName(a2.soa()->nname);
						a2.soa()->rname = AmendName(a2.soa()->rname);
					} else if (a2.type == DNS_TYPE::HTTPS && a2.https()) {
						a2.https()->name = AmendName(a2.https()->name);
					}
					sending.answers.push_back(a2);
				}
			}
		}
		// edns0
		set_edns0(&sending);
		// send
		auto d2 = *d;
		d2.in4_udp.sa4 = task->client_sa4;
		d2.in6_udp.sa6 = task->client_sa6;
		send_dns_message(&d2, task->client_proto, sending, false, false);
		// cahce
		dns::Cache *cache = get_cache(task->type);
		if (cache) {
			cache->insert(task->forward_name, sending, cache_min_ttl());
		}
	}
}

void Behind::process_response(InternalData *d, ProtocolFamilyType const &upstream_proto, dns::Message const &received)
{
	std::shared_ptr<Task> task = take_task_by_id(received.header.id);
	if (!task) return;
	if (task->upstream_proto == upstream_proto && accept_dns_type(task->type)) {
		bool tc = bool(received.header.flags & 0x0200);
		if (tc) { // truncated
			std::string qname = task->forward_name;
			std::vector<Forwarder const *> forwarders = choose_forwarder(qname, 1);
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

void Behind::process_receive(InternalData *d, int upstream_fd)
{
	std::shared_ptr<Task> task = take_task_by_fd(upstream_fd);
	if (task) {
		assert(task->upstream_fd == upstream_fd);

		auto Done = [&](bool deletesocket){
			if (deletesocket) {
				delete_socket(task);
			}
		};
		
		if (task->op == Operation::READING_FROM_CLIENT) {
			process(d, task->upstream_proto);
			return Done(true);
		}
		
		if (task->op == Operation::FORWARD_TO_UPSTREAM_TCP) {
			if (task->connect_in_progress) {
				int upstream_fd = task->upstream_fd;
				int err;
				socklen_t len = sizeof(err);
				getsockopt(upstream_fd, SOL_SOCKET, SO_ERROR, &err, &len);
				if (err == 0) {
					if (send_dns_message(&task->fwdata->d, task->upstream_proto, task->fwdata->msg, true, false)) {
						ctl_del(upstream_fd, task->ev.get());
						task->connect_in_progress = false;
						task->op = Operation::REPLY_TO_CLIENT_TCP;
						push_task(task, 1000, EPOLLIN | EPOLLERR | EPOLLHUP);
						return Done(false);
					}
				}
			}
			return Done(true);
		}
		
		if (task->op == Operation::REPLY_TO_CLIENT_TCP) {
			uint16_t len = 0;
			int n = recv(task->upstream_fd, &len, 2, 0);
			if (n == 2) {
				len = ntohs(len);
				if (len > 0) {
					std::vector<char> buf(len);
					int n = recv(task->upstream_fd, buf.data(), len, 0);
					if (n == len) {
						char const *begin = buf.data();
						char const *end = begin + len;
						dns::Message sending;
						parse_dns_message(begin, end, &sending);
						drop_aa_flag(&sending);
						sending.header.id = task->requester_id;
						send_dns_message(d, task->client_proto, sending, false, false);
						// cahce
						dns::Cache *cache = get_cache(task->type);
						if (cache) {
							cache->insert(task->forward_name, sending, cache_min_ttl());
						}
					}
				}
			}
			return Done(true);
		}
		
		if (task->op == Operation::REPLY_TO_CLIENT_UDP) {
			char buf[4096];
			int n = recv(upstream_fd, buf, sizeof(buf), 0);
			if (n > 0) {
				dns::Message received;
				parse_dns_message(buf, buf + n, &received);
				drop_aa_flag(&received);
				bool tc = bool(received.header.flags & 0x0200);
				if (tc) {
					std::string qname = task->forward_name;
					std::vector<Forwarder const *> forwarders = choose_forwarder(qname, 1);
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
					reply_to_client_udp(d, task, received);
				}
			}
			return Done(true);
		}
	}
	
	delete_socket(upstream_fd, nullptr);
}

void Behind::drop_aa_flag(dns::Message *msg)
{
	msg->header.flags &= ~0x0400;
}

bool Behind::process(InternalData *d, ProtocolFamilyType const &client_proto)
{
	if (client_proto.is_inet4() || client_proto.is_inet6()) {
		std::vector<char> buf;
		buf = read(d, client_proto);
		if (buf.empty()) return false;
		if (buf.size() < 12) return true;
		
		dns::Message received;
		parse_dns_message(buf.data(), buf.data() + buf.size(), &received);
		
		if ((received.header.flags & 0xf800) == 0x0000) { // standard query
			for (auto it = received.questions.begin(); it != received.questions.end(); it++) {
				dns::Question const &q = *it;
				if (client_proto.is_dgram()) {
					process_query_udp(d, client_proto, received, q);
					return true;
				}
				if (client_proto.is_stream()) {
					process_query_tcp(d, client_proto, received, q);
					return true;
				}
			}
		} else if (received.header.flags & 0x8000) { // response
			drop_aa_flag(&received);
			process_response(d, client_proto, received);
			return true;
		}
	}
	return false;
}

void Behind::process_udp(InternalData *d, sa_family_t family)
{
	process(d, {family, SOCK_DGRAM});
}

void Behind::process_tcp(InternalData *d, sa_family_t family)
{
	int sock = -1;
	if (family == AF_INET) {
		socklen_t len = sizeof(d->in4_tcp.sa4);
		sock = accept(d->in4_tcp.listener_fd, (sockaddr *)&d->in4_tcp.sa4, &len);
		d->in4_tcp.fd = sock;
	} else if (family == AF_INET6) {
		socklen_t len = sizeof(d->in6_tcp.sa6);
		sock = accept(d->in6_tcp.listener_fd, (sockaddr *)&d->in6_tcp.sa6, &len);
		d->in6_tcp.fd = sock;
	}
	if (sock != -1) {
		fcntl(sock, F_SETFL, O_NONBLOCK);
		std::shared_ptr<Task> task = make_task(Operation::READING_FROM_CLIENT, next_local_transaction_id());
		task->upstream_fd = sock;
		task->upstream_proto = {family, SOCK_STREAM};
		push_task(task, 3000, EPOLLIN | EPOLLERR | EPOLLHUP);
	}
}



bool Behind::init_socket(void *private_in, ProtocolFamilyType proto)
{
	Behind::InternalData::In *in = static_cast<Behind::InternalData::In *>(private_in);
	
	int sock = socket(proto.family(), proto.socktype(), 0);
	if (sock == INVALID_SOCKET) {
		throw STRERROR("socket: ");
	}
	
	fcntl(sock, F_SETFL, O_NONBLOCK);
	
	{
		int yes = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
		if (proto.is_inet6()) {
			setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&yes, sizeof(yes));
		}
	}

	auto Bind = [&](void *private_in, ProtocolFamilyType const &proto, int sock){
		Behind::InternalData::In *in = static_cast<Behind::InternalData::In *>(private_in);
		int r = SOCKET_ERROR;
		if (proto.is_inet4()) {
			if (m->option.listen4.addr) {
				init_sa4(&in->sa4, (in_addr *)m->option.listen4.addr.to_in4(0), m->option.listen4.port);
				r = ::bind(sock, (struct sockaddr *)&in->sa4, sizeof(in->sa4));
			}
		} else {
			if (m->option.listen6.addr) {
				init_sa6((sockaddr_in6 *)&in->sa6, (in6_addr *)m->option.listen6.addr.to_in6(0), m->option.listen6.port);
				r = ::bind(sock, (struct sockaddr *)&in->sa6, sizeof(in->sa6));
			}
		}
		if (r == SOCKET_ERROR) return false;
		return true;
	};
	
	if (!Bind(in, proto, sock)) {
		// throw STRERROR("bind: ");
		return false;
	}

	char const *proto_str = nullptr;
	
	if (proto.is_dgram()) {
		in->fd = sock;
		proto_str = "udp";
	} else if (proto.is_stream()) {
		if (listen(sock, 5) == SOCKET_ERROR) {
			throw STRERROR("listen: ");
		}
		in->listener_fd = sock;
		proto_str = "tcp";
	}
	
	InetResolver::Addr addr;
	if (proto.is_inet4()) {
		addr.add_in4(&in->sa4.sin_addr.s_addr);
	} else if (proto.is_inet6()) {
		addr.add_in6(&in->sa6.sin6_addr);
	}
	std::string s = addr.to_string(0);
	logprintf(LOG_BOTH, "listen %s port: %s@%d\n", proto_str, s.c_str(), ntohs(in->sa4.sin_port));
	return true;
}

static std::string make_host_name(std::string name, std::string suffix)
{
	if (name[name.size() - 1] == '.') {
		// thru
	} else if (!suffix.empty()) {
		name = name + '.' + suffix;
	}
	return name;
}

Hosts Behind::load_hosts_file(std::string const &suffix, std::string const &path)
{
	Hosts hosts;
	hosts.path = path;

	LineReader reader;
	reader.open(path);
	std::string line;
	while (reader.getline(&line)) {
		std::vector<std::string_view> words = misc::split(line);
		if (words.size() >= 2) {
			std::string_view ip = words[0];
			InetAddrPort addrport = InetAddrPort::parse(std::string(ip));
			if (addrport) {
				for (size_t i = 1; i < words.size(); i++) {
					std::string name(words[i]);
					name = make_host_name(name, suffix);
					hosts.set(name, addrport.addr);
				}
			} else {
				logprintf(LOG_DEFAULT, "invalid IP address in hosts file %s: %s\n", path.c_str(), ip.data());
			}
		}
	}

	return hosts;
}

void Behind::update_hosts_files(bool force)
{
	std::vector<Option::HostsFile> const &hostsfiles = m->option.hostsfiles;

	for (Option::HostsFile const &hf : hostsfiles) {

		struct stat st;
		if (stat(hf.path.c_str(), &st) != 0) {
			logprintf(LOG_DEFAULT, "cannot stat hosts file %s: %s\n", hf.path.c_str(), strerror(errno));
			continue;
		}

		enum {
			None,
			Insert,
			Update,
		} perform = Insert;

		size_t index = 0;

		for (index = 0; index < m->hosts.size(); index++) {
			Hosts const &hosts = m->hosts[index];
			if (hosts.path == hf.path) {
				if (force || hosts.mtime < st.st_mtime) {
					perform = Update;
				} else {
					perform = None;
				}
				break;
			}
		}

		if (perform != None) {
			Hosts hosts = load_hosts_file(hf.suffix, hf.path);
			hosts.mtime = st.st_mtime;
			if (perform == Insert) {
				m->hosts.push_back(std::move(hosts));
			} else if (perform == Update) {
				m->hosts[index] = std::move(hosts);
			}
		}
	}
}

void Behind::initialize_hosts()
{
	std::vector<Option::Host> const &hosts = m->option.hosts;
	std::vector<Option::HostsFile> const &hostsfiles = m->option.hostsfiles;

	m->hosts.clear();

	for (Option::Host const &host : hosts) {
		std::string name = host.name;
		if (!name.empty()) {
			if (name[name.size() - 1] == '.') {
				name = name.substr(0, name.size() - 1);
			}
			std::string name = host.name;
			if (name[name.size() - 1] == '.') {
				// thru
			} else if (!host.suffix.empty()) {
				name = make_host_name(name, host.suffix);
			}
			std::string value = host.address;
			auto addrport = InetAddrPort::parse(value);
			if (!addrport) {
				logprintf(LOG_DEFAULT, "invalid address in hosts: %s\n", value.c_str());
				continue;
			}
			if (m->hosts.empty()) {
				m->hosts.emplace_back();
			}
			m->hosts.back().set(name, addrport.addr);
		}
	}

	update_hosts_files(true);
}

int ev_fd(struct epoll_event *e)
{
	return e->data.fd;
}

void Behind::main()
{
	initialize_hosts();

	m->start_time = misc::get_tick_count();

	InternalData d;
	init_socket(&d.in4_udp, {AF_INET, SOCK_DGRAM});
	init_socket(&d.in6_udp, {AF_INET6, SOCK_DGRAM});
	init_socket(&d.in4_tcp, {AF_INET, SOCK_STREAM});
	init_socket(&d.in6_tcp, {AF_INET6, SOCK_STREAM});
	
	m->socket_mode = SocketMode::EPOLL;

	const int interval_ms = 100;
	
	if (m->socket_mode == SocketMode::SELECT) {
		logprintf(LOG_DEFAULT, "mode: SELECT\n");
		
		ctl_add(d.in4_udp.fd, nullptr, true, false);
		ctl_add(d.in6_udp.fd, nullptr, true, false);
		ctl_add(d.in4_tcp.listener_fd, nullptr, true, false);
		ctl_add(d.in6_tcp.listener_fd, nullptr, true, false);
		
		while (1) {
			fd_set infds;
			fd_set outfds;
			FD_ZERO(&infds);
			FD_ZERO(&outfds);
			int maxfd = -1;
			std::vector<int> infdvec;
			std::vector<int> outfdvec;
			{
				infdvec = m->select_in_fds;
				for (int fd : infdvec) {
					FD_SET(fd, &infds);
					maxfd = std::max(maxfd, fd);
				}
				outfdvec = m->select_out_fds;
				for (int fd : outfdvec) {
					FD_SET(fd, &outfds);
					maxfd = std::max(maxfd, fd);
				}
			}
			timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = interval_ms * 1000;
			select(maxfd + 1, &infds, &outfds, nullptr, &tv);
			
			int fd;
			fd = d.in4_udp.fd;
			if (FD_ISSET(fd, &infds)) {
				FD_CLR(fd, &infds);
				process_udp(&d, AF_INET);
			}
			fd = d.in6_udp.fd;
			if (FD_ISSET(fd, &infds)) {
				FD_CLR(fd, &infds);
				process_udp(&d, AF_INET6);
			}
			fd = d.in4_tcp.listener_fd;
			if (FD_ISSET(fd, &infds)) {
				FD_CLR(fd, &infds);
				process_tcp(&d, AF_INET);
			}
			fd = d.in6_tcp.listener_fd;
			if (FD_ISSET(fd, &infds)) {
				FD_CLR(fd, &infds);
				process_tcp(&d, AF_INET6);
			}
			for (int fd : infdvec) {
				if (FD_ISSET(fd, &infds)) {
					FD_CLR(fd, &infds);
					process_receive(&d, fd);
				}
			}
			for (int fd : outfdvec) {
				if (FD_ISSET(fd, &outfds)) {
					FD_CLR(fd, &outfds);
					process_receive(&d, fd);
				}
			}
			uptime();
			clean();
		}
	} else if (m->socket_mode == SocketMode::EPOLL) {
		logprintf(LOG_DEFAULT, "mode: EPOLL\n");
		
		m->epoll_fd = epoll_create1(0);
		if (m->epoll_fd == -1) {
			throw STRERROR("epoll_create1: ");
		}
		
		auto AddEpoll = [this](Behind::InternalData::In *in, int socktype){
			int fd = -1;
			in->ev = {};
			in->ev.events = EPOLLIN;
			if (socktype == SOCK_DGRAM) {
				fd = in->fd;
			} else if (socktype == SOCK_STREAM) {
				fd = in->listener_fd;
			}
			in->ev.data.fd = fd;
			if (fd != -1) {
				if (ctl_add(fd, &in->ev, true, false) == -1) {
					logprintf(LOG_DEFAULT, "epoll_ctl: %s\n", strerror(errno));
				}
			}
		};
		AddEpoll(&d.in4_udp, SOCK_DGRAM);
		AddEpoll(&d.in6_udp, SOCK_DGRAM);
		AddEpoll(&d.in4_tcp, SOCK_STREAM);
		AddEpoll(&d.in6_tcp, SOCK_STREAM);
		
		while (1) {
			int n = epoll_wait(m->epoll_fd, m->epoll_events.data(), m->epoll_events.size(), interval_ms);
			if (n == -1) {
				if (errno == EINTR) {
					continue;
				}
				throw STRERROR("epoll_wait: ");
			}
			for (int i = 0; i < n; i++) {
				auto fd = m->epoll_events[i].data.fd;
				if (fd == d.in4_udp.fd) {
					process_udp(&d, AF_INET);
				} else if (fd == d.in6_udp.fd) {
					process_udp(&d, AF_INET6);
				} else if (fd == d.in4_tcp.listener_fd) {
					process_tcp(&d, AF_INET);
				} else if (fd == d.in6_tcp.listener_fd) {
					process_tcp(&d, AF_INET6);
				} else {
					process_receive(&d, fd);
				}
			}
			uptime();
			clean();
		}
		::close(m->epoll_fd);
	}
	
	auto CloseSockets = [](std::vector<int> *v){
		for (int fd : *v) {
			closesocket(fd);
		}
		v->clear();
	};

	CloseSockets(&m->select_in_fds);
	CloseSockets(&m->select_out_fds);

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
	// split test
	{
		std::string s = "  abc    \"def  ghi\"  jkl  ";
		std::vector<std::string_view> sv = misc::split(s);
		EXPECT_EQ(sv.size(), 3);
		EXPECT_EQ(std::string(sv[0]), "abc");
		EXPECT_EQ(std::string(sv[1]), "\"def  ghi\"");
		EXPECT_EQ(std::string(sv[2]), "jkl");
	}

	// decode_name test
	
	{
		int r;
		std::string in, out;
		
		in = "\x03" "www" "\x06" "google" "\x03" "com" "\x00";
		r = decode_name(in.data(), in.data() + 16, in.data(), &out);
		EXPECT_EQ(r, 16);
		EXPECT_EQ(out, "www.google.com");
		
		in = "\x03" "www" "\x06" "google" "\x03" "com" "\x00\x00\x00";
		r = decode_name(in.data(), in.data() + 18, in.data(), &out);
		EXPECT_EQ(r, 16);
		EXPECT_EQ(out, "www.google.com");
		
		in = "\x03" "www" "\x00\x00\x00";
		r = decode_name(in.data(), in.data() + 7, in.data(), &out);
		EXPECT_EQ(r, 5);
		EXPECT_EQ(out, "www");
		
		in = "\xc0\x00"; // infinite loop
		r = decode_name(in.data(), in.data() + 2, in.data(), &out);
		EXPECT_EQ(r, 0);
		EXPECT_EQ(out, "");
		
		in = "\x03" "www" "\x06" "google" "\x03" "com" "\xc0\x00"; // infinite loop
		r = decode_name(in.data(), in.data() + 17, in.data(), &out);
		EXPECT_EQ(r, 0);
		EXPECT_EQ(out, "");
	}
	
	// domain filter test
	
	{
		DomainFilter filter;
		filter.add_nxdomain("*.lan");
		filter.add_nxdomain("example.com");
		EXPECT_EQ(filter.find("hoge.lan"), DomainFilter::NXDOMAIN);
		EXPECT_EQ(filter.find("example.com"), DomainFilter::NXDOMAIN);
		EXPECT_EQ(filter.find("ads.example.com"), DomainFilter::NXDOMAIN);
	}
	
	// serializer/desirializer test
	
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
		
		EXPECT_EQ(msg.questions[0].clas, DNS_CLASS::IN);
		EXPECT_EQ(msg.questions[0].type, DNS_TYPE::A);
		EXPECT_EQ(msg.questions[0].name, "www.google.com");
		
		EXPECT_EQ(msg.answers[0].clas, DNS_CLASS::IN);
		EXPECT_EQ(msg.answers[0].type, DNS_TYPE::A);
		EXPECT_EQ(msg.answers[0].name, "www.google.com");
		EXPECT_EQ(to_string(msg.answers[0].bin), std::string("\x8e\xfa\xc2\xc4", 4));
		EXPECT_EQ(msg.answers[0].ttl, 300);
		
		{
			Packet response = make_dns_packet(msg, false);
			
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
		
		EXPECT_EQ(msg.questions[0].clas, DNS_CLASS::IN);
		EXPECT_EQ(msg.questions[0].type, DNS_TYPE::A);
		EXPECT_EQ(msg.questions[0].name, "www.amazon.co.jp");
		
		EXPECT_EQ(msg.answers[0].clas, DNS_CLASS::IN);
		EXPECT_EQ(msg.answers[0].type, DNS_TYPE::CNAME);
		EXPECT_EQ(msg.answers[0].name, "www.amazon.co.jp");
		EXPECT_EQ(msg.answers[0].cname()->cname, "tp.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(msg.answers[0].ttl, 300);
		
		EXPECT_EQ(msg.answers[1].clas, DNS_CLASS::IN);
		EXPECT_EQ(msg.answers[1].type, DNS_TYPE::CNAME);
		EXPECT_EQ(msg.answers[1].name, "tp.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(msg.answers[1].cname()->cname, "cf.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(msg.answers[1].ttl, 300);
		
		EXPECT_EQ(msg.answers[2].clas, DNS_CLASS::IN);
		EXPECT_EQ(msg.answers[2].type, DNS_TYPE::A);
		EXPECT_EQ(msg.answers[2].name, "cf.4d5ad1d2b-frontier.amazon.co.jp");
		EXPECT_EQ(to_string(msg.answers[2].bin), std::string("\x03\xa8\xfb\x86", 4));
		EXPECT_EQ(msg.answers[2].ttl, 300);
		
		{
			Packet response = make_dns_packet(msg, false);
			
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
		
		EXPECT_EQ(msg.questions[0].clas, DNS_CLASS::IN);
		EXPECT_EQ(msg.questions[0].type, DNS_TYPE::A);
		EXPECT_EQ(msg.questions[0].name, "doubleclick.net");
	}
}

