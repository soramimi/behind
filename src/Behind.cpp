#include "Behind.h"
#include "ChaCha20.h"
#include "LineReader.h"
#include "Logger.h"
#include "misc.h"
#include "rwfile.h"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <list>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <optional>
#include <regex>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#define stricmp(A, B) strcasecmp(A, B)
#define STRERROR(S) (std::string(S) + strerror(errno))
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket(S) close(S)

#define BEHIND_UPSTREAM_UDP_CHANNELS_PER_FORWARDER 4

static inline uint16_t ntohs_p(void const *p)
{
	uint16_t v;
	memcpy(&v, p, 2);
	return ntohs(v);
}

static inline uint32_t ntohl_p(void const *p)
{
	uint32_t v;
	memcpy(&v, p, 4);
	return ntohl(v);
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
	return { };
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
static inline bool operator==(const Question &l, const Question &r)
{
	if (l.name != r.name) return false;
	if (l.type != r.type) return false;
	if (l.clas != r.clas) return false;
	return true;
}

struct CNAME {
	std::string cname;
};

struct PTR {
	std::string ptr;
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
	// Unknown RDATA can only be copied to a newly encoded packet when it does
	// not contain a compression pointer.  Such pointers are relative to the
	// original DNS message and cannot be rebased without knowing the RR type.
	bool cacheable = true;

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

	// ptr

	void set_ptr(std::shared_ptr<PTR> ptr)
	{
		sp = ptr;
	}
	PTR const *ptr() const
	{
		if (type == DNS_TYPE::PTR && sp) {
			return std::static_pointer_cast<PTR>(sp).get();
		}
		return nullptr;
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
			struct sockaddr_in a = { };
			memcpy(&a.sin_addr.s_addr, bin.data(), sizeof(a.sin_addr.s_addr));
			return addr_to_string(AF_INET, (struct sockaddr *)&a);
		} else if (type == DNS_TYPE::AAAA && bin.size() == 16) {
			struct sockaddr_in6 a = { };
			memcpy(&a.sin6_addr.s6_addr, bin.data(), 16);
			return addr_to_string(AF_INET6, (struct sockaddr *)&a);
		} else if (type == DNS_TYPE::CNAME && cname()) {
			CNAME const *p = cname();
			if (p) {
				return p->cname;
			}
		} else if (type == DNS_TYPE::PTR && ptr()) {
			PTR const *p = ptr();
			if (p) {
				return p->ptr;
			}
		}
		return { };
	}
};

static inline bool operator==(const Record &l, const Record &r)
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

	static Message SERVFAIL(char const *file, int line)
	{
		(void)file;
		logprintf(LOG_STDERR, "--- (debug) servfail: line=%d\n", line);
		Message response;
		response.header.flags = 0x8182; // SERVFAIL
		return response;
	}
};

static void normalize_negative_ttl(Message *message)
{
	if (!message) return;
	uint16_t rcode = message->header.flags & 0x000f;
	if (rcode != 3 && !(rcode == 0 && message->answers.empty())) return;
	for (Record &record : message->authorities) {
		if (record.type == DNS_TYPE::SOA && record.soa()) {
			record.ttl = std::min(record.ttl, record.soa()->minimum);
			return;
		}
	}
}

struct CacheKey {
	std::string name;
	DNS_TYPE type = DNS_TYPE::A;
	DNS_CLASS clas = DNS_CLASS::IN;
	bool operator==(CacheKey const &other) const
	{
		return type == other.type && clas == other.clas && name == other.name;
	}
};

struct CacheKeyHash {
	size_t operator()(CacheKey const &key) const
	{
		size_t h = std::hash<std::string> { }(key.name);
		h ^= (size_t)key.type + 0x9e3779b9 + (h << 6) + (h >> 2);
		h ^= (size_t)key.clas + 0x9e3779b9 + (h << 6) + (h >> 2);
		return h;
	}
};

class Cache {
private:
	// Entry-count floor and ceiling. The effective cap is derived from
	// max_bytes_ (see set_max_bytes) because a fixed 4096-entry limit was
	// reached at only a few MB, so max-cache-bytes could never bind and the
	// documented 64 MB default was unreachable. Cache hit rate is the largest
	// single lever on real-world throughput: every miss costs an upstream round
	// trip and occupies a max-tasks slot.
	static constexpr size_t MIN_ENTRIES = 4096;
	static constexpr size_t MAX_ENTRIES_LIMIT = 1000000;
	static constexpr size_t ASSUMED_ENTRY_BYTES = 512;
	struct Item {
		CacheKey key;
		uint64_t expire = 0;
		size_t charge = 0;
		Message value;
	};
	std::list<Item> items_;
	std::unordered_map<CacheKey, std::list<Item>::iterator, CacheKeyHash> index_;
	size_t bytes_ = 0;
	size_t max_bytes_ = 64 * 1024 * 1024;
	size_t max_entries_ = MAX_ENTRIES_LIMIT;
	size_t max_entry_size_ = 65535;
	uint32_t max_ttl_ = 86400;

	static CacheKey make_key(std::string const &name, DNS_TYPE type, DNS_CLASS clas)
	{
		return { misc::strtolower(name), type, clas };
	}
	static bool add_size(size_t *total, size_t value)
	{
		if (value > SIZE_MAX - *total) return false;
		*total += value;
		return true;
	}
	static size_t record_size(Record const &record)
	{
		size_t size = sizeof(record) + record.name.size() + record.bin.size();
		auto Add = [&](size_t n) { return add_size(&size, n); };
		if (auto p = record.cname()) {
			if (!Add(sizeof(*p) + p->cname.size())) return SIZE_MAX;
		}
		if (auto p = record.ptr()) {
			if (!Add(sizeof(*p) + p->ptr.size())) return SIZE_MAX;
		}
		if (auto p = record.ns()) {
			if (!Add(sizeof(*p) + p->nsname.size())) return SIZE_MAX;
		}
		if (auto p = record.mx()) {
			if (!Add(sizeof(*p) + p->exchange.size())) return SIZE_MAX;
		}
		if (auto p = record.soa()) {
			if (!Add(sizeof(*p)) || !Add(p->nname.size()) || !Add(p->rname.size())) return SIZE_MAX;
		}
		if (auto p = record.https()) {
			if (!Add(sizeof(*p)) || !Add(p->name.size()) || !Add(p->data.size())) return SIZE_MAX;
		}
		return size;
	}
	static size_t message_size(CacheKey const &key, Message const &value)
	{
		size_t size = sizeof(Item) + key.name.size();
		for (Question const &q : value.questions) {
			if (!add_size(&size, sizeof(q)) || !add_size(&size, q.name.size())) return SIZE_MAX;
		}
		for (auto const *records : { &value.answers, &value.authorities }) {
			for (Record const &record : *records) {
				size_t amount = record_size(record);
				if (amount == SIZE_MAX || !add_size(&size, amount)) return SIZE_MAX;
			}
		}
		return size;
	}
	void erase(std::list<Item>::iterator it)
	{
		bytes_ = it->charge <= bytes_ ? bytes_ - it->charge : 0;
		index_.erase(it->key);
		items_.erase(it);
	}
	static void update_ttls(std::vector<Record> *records, uint64_t now)
	{
		for (Record &record : *records) {
			record.ttl = now < record.expire
				? (uint32_t)((record.expire - now) / 1000)
				: 0;
		}
	}
	void insert_with_ttl(CacheKey key, Message value, uint32_t ttl)
	{
		if (ttl == 0) return;
		ttl = std::min(ttl, max_ttl_);
		uint64_t now = misc::get_tick_count();
		uint64_t expire = now + (uint64_t)ttl * 1000;
		value.additionals.clear();
		for (auto *records : { &value.answers, &value.authorities }) {
			for (Record &record : *records) {
				uint32_t record_ttl = std::min(record.ttl, max_ttl_);
				record.expire = std::min(expire,
					now + (uint64_t)record_ttl * 1000);
			}
		}
		size_t charge = message_size(key, value);
		if (charge == SIZE_MAX || charge > max_entry_size_ || charge > max_bytes_) return;
		auto found = index_.find(key);
		if (found != index_.end()) erase(found->second);
		while (!items_.empty() && (items_.size() >= max_entries_ || charge > max_bytes_ - bytes_)) {
			erase(std::prev(items_.end()));
		}
		items_.push_front({ std::move(key), expire, charge, std::move(value) });
		bytes_ += charge;
		index_[items_.front().key] = items_.begin();
	}

public:
	void set_max_entry_size(size_t value) { max_entry_size_ = value; }
	void set_max_bytes(size_t value)
	{
		max_bytes_ = value;
		// bytes_/max_bytes_ is the real safety bound; the entry count only keeps
		// the list and index from growing pathologically long for tiny entries.
		max_entries_ = std::clamp(value / ASSUMED_ENTRY_BYTES, MIN_ENTRIES, MAX_ENTRIES_LIMIT);
	}
	void set_max_ttl(uint32_t value) { max_ttl_ = value; }
	size_t entry_count() const { return items_.size(); }
	size_t byte_count() const { return bytes_; }

	std::optional<Message> find(std::string const &name, DNS_TYPE type, DNS_CLASS clas)
	{
		CacheKey key = make_key(name, type, clas);
		auto found = index_.find(key);
		if (found == index_.end()) return std::nullopt;
		uint64_t now = misc::get_tick_count();
		auto item = found->second;
		if (now >= item->expire) {
			erase(item);
			return std::nullopt;
		}
		Message value = item->value;
		update_ttls(&value.answers, now);
		update_ttls(&value.authorities, now);
		items_.splice(items_.begin(), items_, item);
		found->second = items_.begin();
		return value;
	}

	void insert(std::string const &name, DNS_TYPE type, DNS_CLASS clas, Message const &value)
	{
		uint16_t rcode = value.header.flags & 0x000f;
		uint32_t ttl = UINT32_MAX;
		if (rcode == 3 || (rcode == 0 && value.answers.empty())) {
			bool found_soa = false;
			for (Record const &record : value.authorities) {
				if (record.type == DNS_TYPE::SOA && record.soa()) {
					ttl = std::min(record.ttl, record.soa()->minimum);
					found_soa = true;
					break;
				}
			}
			if (!found_soa) return;
		} else if (rcode == 0 && !value.answers.empty()) {
			for (Record const &record : value.answers) {
				if (record.ttl == 0) return;
				ttl = std::min(ttl, record.ttl);
			}
		} else {
			return;
		}
		if (ttl == UINT32_MAX || ttl == 0) return;
		insert_with_ttl(make_key(name, type, clas), value, ttl);
	}

	void insert_failure(std::string const &name, DNS_TYPE type, DNS_CLASS clas, Message const &value, uint32_t ttl = 5)
	{
		insert_with_ttl(make_key(name, type, clas), value, std::min<uint32_t>(300, std::max<uint32_t>(1, ttl)));
	}
};

} // namespace dns

struct Behind::PendingQuery {
	struct Waiter {
		ProtocolFamilyType proto;
		uint16_t requester_id = 0;
		uint16_t udp_payload = 0;
		std::string request_name;
		union {
			sockaddr_in sa4;
			sockaddr_in6 sa6;
		};
	};
	std::string key;
	uint32_t transaction_id = 0;
	std::vector<Waiter> waiters;
};

static std::string pending_query_key(dns::Question const &question)
{
	std::string key = misc::strtolower(question.name);
	key.push_back('\0');
	key.append(std::to_string((uint16_t)question.type));
	key.push_back('/');
	key.append(std::to_string((uint16_t)question.clas));
	return key;
}

struct Behind::Task {
	Behind::Operation op = Operation::NONE;
	bool connect_in_progress = false;
	bool used_edns = true;
	std::shared_ptr<Behind::ForwardingThreadData> fwdata;
	std::shared_ptr<Behind::PendingQuery> pending;
	uint64_t timestamp = 0;
	int timeout = 1000;
	uint32_t local_transaction_id = 0;
	uint16_t upstream_id = 0;
	uint16_t requester_id = 0;
	DNS_TYPE type = DNS_TYPE::A;
	DNS_CLASS clas = DNS_CLASS::IN;
	ProtocolFamilyType client_proto;
	ProtocolFamilyType upstream_proto;
	int upstream_fd = -1;
	int client_fd = -1;
	std::vector<char> buffer;
	size_t send_offset = 0;
	uint16_t client_udp_payload = 0;
	std::shared_ptr<epoll_event> ev = std::make_shared<epoll_event>();
	union {
		sockaddr_in client_sa4;
		sockaddr_in6 client_sa6;
	};
	std::string request_name;
	std::string forward_name;
	Forwarder forwarder;
	// TCP stream reassembly state
	std::vector<char> recv_buffer;
	size_t recv_expected = 0;
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

struct Behind::UdpChannel {
	ProtocolFamilyType proto;
	Forwarder forwarder;
	int fd = -1;
	size_t active_queries = 0;
	std::shared_ptr<epoll_event> ev = std::make_shared<epoll_event>();
};

struct Behind::UdpQuery {
	uint64_t timestamp = 0;
	int timeout = 1000;
	uint32_t local_transaction_id = 0;
	uint16_t upstream_id = 0;
	DNS_TYPE type = DNS_TYPE::A;
	DNS_CLASS clas = DNS_CLASS::IN;
	ProtocolFamilyType client_proto;
	ProtocolFamilyType upstream_proto;
	uint16_t client_udp_payload = 0;
	std::shared_ptr<Behind::PendingQuery> pending;
	std::string request_name;
	std::string forward_name;
	Forwarder forwarder;
	bool used_edns = true;
	int channel_fd = -1;
};

namespace {

struct ClientNetwork {
	sa_family_t family = AF_UNSPEC;
	std::array<uint8_t, 16> address { };
	uint8_t prefix = 0;
};

struct RateBucket {
	double tokens = 0;
	uint64_t updated = 0;
	uint64_t last_seen = 0;
	uint64_t last_limited_log = 0;
};

uint64_t udp_socket_txid_key(int fd, uint16_t txid)
{
	return ((uint64_t)(uint32_t)fd << 32) | (uint64_t)txid;
}

bool same_forwarder_endpoint(Forwarder const &l, Forwarder const &r)
{
	return l.af_type == r.af_type && l.port == r.port && memcmp(l.addr, r.addr, sizeof(l.addr)) == 0;
}

bool parse_client_network(std::string text, ClientNetwork *out)
{
	if (!out || text.empty()) return false;
	size_t slash = text.find('/');
	std::string address = text.substr(0, slash);
	std::string prefix_text = slash == std::string::npos ? std::string() : text.substr(slash + 1);
	if (address.empty() || (slash != std::string::npos && prefix_text.empty())) return false;

	ClientNetwork parsed;
	if (inet_pton(AF_INET, address.c_str(), parsed.address.data()) == 1) {
		parsed.family = AF_INET;
		parsed.prefix = 32;
	} else if (inet_pton(AF_INET6, address.c_str(), parsed.address.data()) == 1) {
		parsed.family = AF_INET6;
		parsed.prefix = 128;
	} else {
		return false;
	}
	if (!prefix_text.empty()) {
		char *end = nullptr;
		errno = 0;
		long value = strtol(prefix_text.c_str(), &end, 10);
		int maximum = parsed.family == AF_INET ? 32 : 128;
		if (errno || !end || *end || value < 0 || value > maximum) return false;
		parsed.prefix = (uint8_t)value;
	}
	*out = parsed;
	return true;
}

bool network_contains(ClientNetwork const &network, sa_family_t family, void const *address)
{
	if (!address || network.family != family) return false;
	size_t bytes = family == AF_INET ? 4 : 16;
	auto candidate = static_cast<uint8_t const *>(address);
	size_t whole = network.prefix / 8;
	uint8_t remaining = network.prefix % 8;
	if (whole && memcmp(network.address.data(), candidate, whole) != 0) return false;
	if (remaining) {
		uint8_t mask = (uint8_t)(0xffU << (8 - remaining));
		if ((network.address[whole] & mask) != (candidate[whole] & mask)) return false;
	}
	return whole <= bytes;
}

std::string client_key(sa_family_t family, void const *address)
{
	char text[INET6_ADDRSTRLEN] = { };
	if (!address || !inet_ntop(family, address, text, sizeof(text))) return { };
	return std::string(family == AF_INET ? "4:" : "6:") + text;
}

} // namespace

struct Behind::Private {
	Options options;

	ChaCha20 rng;

	uint64_t start_time = 0;
	uint64_t last_uptime_min = 0;
	uint64_t last_hosts_check = 0;
	uint64_t last_maintenance = 0;

	std::vector<Hosts> hosts;
	uint32_t local_transaction_id = 0;
	InetResolver resolver;

	Behind::SocketMode socket_mode;
	fd_set readfds;
	int epoll_fd = -1;
	std::vector<int> select_in_fds;
	std::vector<int> select_out_fds;
	std::vector<epoll_event> epoll_events = std::vector<epoll_event>(256);

	dns::Cache dns_cache;
	// Active forwarding tasks, indexed for O(1) dispatch.
	// tasks_by_fd: upstream_fd -> task. Each task owns a unique socket, so the
	//   fd is a unique key; this is the hot lookup in process_receive().
	// udp_queries_by_local_txid: local_transaction_id -> in-flight UDP query.
	//   A single client query fans out to udp-multiple-forwarding upstreams that
	//   share one local transaction id, so this MUST be a multimap: it is the
	//   authoritative registry of in-flight upstream queries and therefore also
	//   what active_task_count() counts and what clean() scans for deadlines.
	//   Erase by (txid, query) identity so a finishing query cannot unregister
	//   its sibling; see erase_udp_query_by_txid().
	// udp_queries_by_socket_txid: (channel_fd, upstream_id) -> in-flight query.
	//   allocate_udp_upstream_id() keeps the key unique among live queries.
	std::unordered_map<int, std::shared_ptr<Behind::Task>> tasks_by_fd;
	std::unordered_multimap<uint32_t, std::shared_ptr<Behind::UdpQuery>> udp_queries_by_local_txid;
	std::unordered_multimap<uint64_t, std::shared_ptr<Behind::UdpQuery>> udp_queries_by_socket_txid;
	std::unordered_map<std::string, std::shared_ptr<Behind::PendingQuery>> pending_udp;
	std::vector<std::shared_ptr<Behind::UdpChannel>> udp_channels;
	std::unordered_map<int, std::shared_ptr<Behind::UdpChannel>> udp_channels_by_fd;
	std::vector<Forwarder> forwarders;
	bool forwarders_valid = true;
	bool hosts_files_valid = true;
	std::vector<ClientNetwork> allowed_clients;
	RateBucket global_rate;
	std::unordered_map<std::string, RateBucket> client_rates;
	uint64_t last_rate_cleanup = 0;
	std::unordered_map<int, uint64_t> paused_listeners;
	int clean_state = 0;
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

bool Behind::validate_options(Options const &opts, std::string *error)
{
	auto Fail = [&](std::string message) {
		if (error) *error = std::move(message);
		return false;
	};
	if (!opts.listen4.addr && !opts.listen6.addr) {
		return Fail("at least one listen address is required");
	}
	if ((opts.listen4.addr && opts.listen4.port == 0) || (opts.listen6.addr && opts.listen6.port == 0)) {
		return Fail("listen port must be between 1 and 65535");
	}
	if (opts.max_tasks == 0 || opts.max_tasks > 50000) {
		return Fail("max-tasks must be between 1 and 50000");
	}
	struct rlimit file_limit = { };
	if (getrlimit(RLIMIT_NOFILE, &file_limit) == 0 && file_limit.rlim_cur != RLIM_INFINITY) {
		rlim_t safe_tasks = file_limit.rlim_cur > 32 ? (file_limit.rlim_cur - 16) / 2 : 0;
		if ((rlim_t)opts.max_tasks > safe_tasks) {
			return Fail("max-tasks exceeds the safe open-file limit (maximum " + std::to_string((uint64_t)safe_tasks) + ")");
		}
	}
	if (opts.max_cache_entry_size == 0 || opts.max_cache_bytes == 0 || opts.max_cache_entry_size > opts.max_cache_bytes) {
		return Fail("max-cache-entry-size must not exceed max-cache-bytes");
	}
	if (opts.max_ttl == 0) return Fail("max-ttl must be greater than zero");
	if (opts.edns0_buffer_size < 512) return Fail("edns0-buffer-size must be at least 512");
	if (opts.rate_limit_qps == 0 || opts.rate_limit_burst == 0) {
		return Fail("rate limits must be greater than zero");
	}
	if (opts.upstream_timeout_ms < 100 || opts.upstream_timeout_ms > 300000) {
		return Fail("upstream-timeout-ms must be between 100 and 300000");
	}
	for (std::string const &text : opts.allow_clients) {
		ClientNetwork network;
		if (!parse_client_network(text, &network)) {
			return Fail("invalid allow-client network: " + text);
		}
	}
	for (Options::Zone const &zone : opts.forward_addr) {
		if (zone.zone.empty() || zone.zone.back() != '.') {
			return Fail("forward zone must be an absolute DNS suffix");
		}
		InetAddrPort numeric = InetAddrPort::parse(zone.name);
		if (!numeric) {
			bool looks_like_ipv4 = !zone.name.empty() && std::all_of(zone.name.begin(), zone.name.end(), [](unsigned char c) {
				return isdigit(c) || c == '.';
			});
			if (looks_like_ipv4 || zone.name.find(':') != std::string::npos || zone.name.find('[') != std::string::npos || zone.name.find(']') != std::string::npos || zone.name.find('@') != std::string::npos || !misc::is_valid_domain(zone.name)) {
				return Fail("invalid forward address: " + zone.name);
			}
		} else if (zone.name.find('@') != std::string::npos && numeric.port == 0) {
			return Fail("invalid forward port: " + zone.name);
		}
	}
	if (error) error->clear();
	return true;
}

Behind::Behind(const Options &opts)
	: m(new Private())
{
	m->options = opts;
	m->epoll_events.resize(std::max<size_t>(256, opts.max_tasks + 8));
	std::vector<std::string> allowed = opts.allow_clients;
	if (allowed.empty()) {
		allowed = { "127.0.0.0/8", "::1/128" };
	}
	for (std::string const &text : allowed) {
		ClientNetwork network;
		if (parse_client_network(text, &network)) {
			m->allowed_clients.push_back(network);
		}
	}
	m->global_rate.tokens = opts.rate_limit_burst;
	m->global_rate.updated = m->global_rate.last_seen = misc::get_tick_count();

	m->dns_cache.set_max_entry_size(opts.max_cache_entry_size);
	m->dns_cache.set_max_bytes(opts.max_cache_bytes);
	m->dns_cache.set_max_ttl(opts.max_ttl);

	init_forwarder();
}

Behind::~Behind()
{
	delete m;
}

inline bool Behind::eqi(const std::string &l, const std::string &r)
{
	return stricmp(l.c_str(), r.c_str()) == 0;
}

inline uint16_t Behind::listen_port() const
{
	return m->options.listen_port;
}

inline void Behind::write(std::vector<char> *out, char c)
{
	out->push_back(c);
}

inline void Behind::write(std::vector<char> *out, const char *src, int len)
{
	if (src && len > 0) {
		out->insert(out->end(), src, src + len);
	}
}

inline void Behind::write_us(std::vector<char> *out, uint16_t v)
{
	v = htons(v);
	write(out, (char const *)&v, 2);
}

inline void Behind::write_ul(std::vector<char> *out, uint32_t v)
{
	v = htonl(v);
	write(out, (char const *)&v, 4);
}

inline void Behind::write_us(void *out, uint16_t v)
{
	v = htons(v);
	memcpy(out, (char const *)&v, 2);
}

inline void Behind::write_ul(void *out, uint32_t v)
{
	v = htonl(v);
	memcpy(out, (char const *)&v, 4);
}

bool Behind::write_name(std::vector<char> *out, NameMap *namemap, const std::string &name)
{
	if (!out) return false;
	if (name.empty()) {
		write(out, (char)0);
		return true;
	}

	// The in-memory form uses dots as label separators, so allowing a dot (or
	// a NUL/control byte) as label data would create two spellings for the same
	// wire name and, consequently, ambiguous cache/filter keys.
	size_t wire_len = 1; // root label
	for (size_t pos = 0; pos < name.size();) {
		size_t dot = name.find('.', pos);
		size_t label_end = dot == std::string::npos ? name.size() : dot;
		size_t len = label_end - pos;
		if (len < 1 || len > 63) return false;
		wire_len += 1 + len;
		if (wire_len > 255) return false;
		for (size_t i = pos; i < label_end; i++) {
			unsigned char c = (unsigned char)name[i];
			if (c == 0 || c == '.' || c < 0x20 || c == 0x7f) return false;
		}
		if (dot == std::string::npos) break;
		pos = dot + 1;
		if (pos == name.size()) return false; // trailing empty label
	}

	for (size_t pos = 0; pos < name.size();) {
		size_t dot = name.find('.', pos);
		size_t label_end = dot == std::string::npos ? name.size() : dot;
		size_t len = label_end - pos;
		if (namemap) {
			auto it = namemap->find(name.substr(pos));
			if (it != namemap->end() && it->second <= 0x3fff) {
				write_us(out, (uint16_t)(0xc000 | it->second));
				return true;
			}
		}
		if (namemap) {
			size_t base = namemap->offset();
			if (out->size() >= base && out->size() - base <= 0x3fff) {
				namemap->set(name.substr(pos), out->size());
			}
		}
		write(out, (char)len);
		write(out, name.data() + pos, (int)len);
		if (dot == std::string::npos) break;
		pos = dot + 1;
	}
	write(out, (char)0);
	return true;
}

int Behind::decode_name(const char *begin, const char *end, const char *ptr, std::string *name)
{
	if (!name) return 0;
	name->clear();
	if (!begin || !end || !ptr || begin > ptr || ptr >= end) return 0;

	std::string decoded;
	decoded.reserve(253);
	char const *cursor = ptr;
	size_t consumed = 0;
	size_t expanded_wire_len = 1; // terminating root label
	bool jumped = false;
	size_t jump_count = 0;
	while (cursor < end) {
		uint8_t n = (uint8_t)*cursor;
		uint8_t bits = n & 0xc0;
		if (bits == 0xc0) {
			if (++jump_count > 128) break;
			if (end - cursor < 2) break;
			size_t offset = ((size_t)(n & 0x3f) << 8) | (uint8_t)cursor[1];
			size_t packet_size = (size_t)(end - begin);
			size_t cursor_offset = (size_t)(cursor - begin);
			// Requiring a backward pointer both matches normal DNS compression and
			// makes pointer cycles impossible without an allocation-heavy visited set.
			if (offset >= packet_size || offset >= cursor_offset) break;
			if (!jumped) consumed += 2;
			cursor = begin + offset;
			jumped = true;
			continue;
		}
		if (bits != 0) break; // reserved label encodings

		cursor++;
		if (!jumped) consumed++;
		if (n == 0) {
			*name = std::move(decoded);
			return (int)consumed;
		}
		if (end - cursor < n) break;
		if (expanded_wire_len + 1 + n > 255) break;
		if (decoded.size() + (decoded.empty() ? 0 : 1) + n > 253) break;
		for (size_t i = 0; i < n; i++) {
			unsigned char c = (unsigned char)cursor[i];
			if (c == 0 || c == '.' || c < 0x20 || c == 0x7f) return 0;
		}
		if (!decoded.empty()) decoded.push_back('.');
		decoded.append(cursor, n);
		expanded_wire_len += 1 + n;
		if (!jumped) consumed += n;
		cursor += n;
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
	if (!out) return false;
	size_t record_start = out->size();
	auto Fail = [&]() {
		out->resize(record_start);
		return false;
	};
	if (!write_name(out, namemap, name)) return Fail();
	write_us(out, (int)item.type);
	write_us(out, (int)item.clas);
	write_ul(out, item.ttl);

	size_t i = out->size();
	write_us(out, 0);
	if (item.type == DNS_TYPE::PTR) {
		dns::PTR const *p = item.ptr();
		if (!p) return Fail();
		if (!write_name(out, namemap, p->ptr)) return Fail();
	} else if (item.type == DNS_TYPE::CNAME) {
		dns::CNAME const *cname = item.cname();
		if (!cname) return Fail();
		if (!write_name(out, namemap, cname->cname)) return Fail();
	} else if (item.type == DNS_TYPE::NS) {
		dns::NS const *ns = item.ns();
		if (!ns) return Fail();
		if (!write_name(out, namemap, ns->nsname)) return Fail();
	} else if (item.type == DNS_TYPE::MX) {
		dns::MX const *mx = item.mx();
		if (!mx) return Fail();
		write_us(out, mx->preference);
		if (!write_name(out, namemap, mx->exchange)) return Fail();
	} else if (item.type == DNS_TYPE::SOA) {
		auto WriteSOA = [&](dns::SOA const &soa) {
			if (!write_name(out, namemap, soa.nname)) return false;
			if (!write_name(out, namemap, soa.rname)) return false;
			write_ul(out, soa.serial);
			write_ul(out, soa.refresh);
			write_ul(out, soa.retry);
			write_ul(out, soa.expire);
			write_ul(out, soa.minimum);
			return true;
		};
		if (!item.soa() || !WriteSOA(*item.soa())) return Fail();
	} else if (item.type == DNS_TYPE::HTTPS) {
		dns::HTTPS const *https = item.https();
		if (!https) return Fail();
		write_us(out, https->priority);
		if (!write_name(out, namemap, https->name)) return Fail();
		if (!https->data.empty()) {
			if (https->data.size() > UINT16_MAX) return Fail();
			bool first = true;
			uint16_t previous_key = 0;
			for (size_t p = 0; p < https->data.size();) {
				if (https->data.size() - p < 4) return Fail();
				uint16_t key = ((uint8_t)https->data[p] << 8) | (uint8_t)https->data[p + 1];
				size_t n = ((uint8_t)https->data[p + 2] << 8) | (uint8_t)https->data[p + 3];
				if (!first && key <= previous_key) return Fail();
				first = false;
				previous_key = key;
				p += 4;
				if (n > https->data.size() - p) return Fail();
				p += n;
			}
			write(out, https->data.data(), (int)https->data.size());
		}
	} else {
		size_t len = item.bin.size();
		if (len > UINT16_MAX) return Fail();
		if (item.type == DNS_TYPE::A) {
			if (len != 4) return Fail();
		} else if (item.type == DNS_TYPE::AAAA) {
			if (len != 16) return Fail();
		} else if (item.type == DNS_TYPE::TXT) {
			// TXT RDATA is one or more length-prefixed character strings.
			if (len == 0) return Fail();
			for (size_t p = 0; p < len;) {
				size_t n = item.bin[p++];
				if (n > len - p) return Fail();
				p += n;
			}
		} else if (item.type == DNS_TYPE::OPT) {
			// Validate the option-code/option-length framing while preserving data.
			for (size_t p = 0; p < len;) {
				if (len - p < 4) return Fail();
				size_t n = ((size_t)item.bin[p + 2] << 8) | item.bin[p + 3];
				p += 4;
				if (n > len - p) return Fail();
				p += n;
			}
		} else if (!item.cacheable) {
			// Raw data containing an original-message compression pointer cannot
			// safely be copied to a packet whose layout may differ.
			return Fail();
		}
		write(out, (char const *)item.bin.data(), (int)len);
	}
	size_t rdlen = out->size() - i - 2;
	if (rdlen > UINT16_MAX) return Fail();
	write_us(&out->at(i), (uint16_t)rdlen);
	return true;
}

int Behind::parse_question_section(const char *begin, const char *end, const char *ptr, dns::Question *out)
{
	if (!out) return 0;
	int n = decode_name(begin, end, ptr, &out->name);
	if (n > 0) {
		char const *start = ptr;
		ptr += n;
		if (end - ptr < 4) return 0;
		out->type = (DNS_TYPE)ntohs_p(ptr);
		out->clas = (DNS_CLASS)ntohs_p(ptr + 2);
		ptr += 4;
		return ptr - start;
	}
	return 0;
}

std::vector<Forwarder const *> Behind::choose_forwarder(std::string const &name, size_t max) const
{
	std::vector<Forwarder const *> default_forwarders;
	std::vector<Forwarder const *> matched_forwarders;
	// Longest match wins. Collecting every matching zone instead would make
	// overlapping zones behave randomly: with both "example.com." and
	// "sub.example.com." configured, a query for host.sub.example.com matched
	// both, so UDP fanned out to both upstreams (first answer wins) and TCP
	// picked one at random - roughly half of the queries went to the upstream
	// for the less specific zone. The zone invariant (non-empty, absolute) is
	// enforced at configuration time by validate_options().
	size_t best_zone_length = 0;

	for (Forwarder const &f : m->forwarders) {
		if (f) {
			size_t n = f.zone.size();
			if (n == 1) {
				default_forwarders.push_back(&f);
			} else if (n > 1) {
				if (n < best_zone_length) continue;
				size_t zone_length = n;
				n--;
				size_t i = name.size();
				if (i >= n) {
					i -= n;
					if (i == 0 || name[i - 1] == '.') {
						auto Compare = [&]() {
							for (size_t j = 0; j < n; j++) {
								if (tolower((unsigned char)name[i + j]) != tolower((unsigned char)f.zone[j])) {
									return false;
								}
							}
							return true;
						};
						if (Compare()) {
							if (zone_length > best_zone_length) {
								best_zone_length = zone_length;
								matched_forwarders.clear();
							}
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
		size_t count = std::min((size_t)max, n);
		for (size_t i = 0; i < count; i++) {
			size_t j = i + (size_t)(m->rng.next_u32() % (uint32_t)(n - i));
			std::swap(forwarders->at(i), forwarders->at(j));
		}
		forwarders->resize(count);
	}

	return *forwarders;
}

std::optional<TransactionID> Behind::allocate_txid(Forwarder const &fw)
{
	constexpr int max_retry = 100;
	TransactionID item;
	item.d->k.af_type = fw.af_type;
	memcpy(item.d->k.addr, fw.addr, sizeof(item.d->k.addr));
	item.d->timestamp = misc::get_tick_count();
	for (int retry = 0; retry < max_retry; retry++) {
		item.d->k.txid = m->rng.next_u32() & 0xffff;
		auto it = active_txids_.find(item);
		if (it == active_txids_.end()) {
			active_txids_.insert({ item });
			logprintf(LOG_DEFAULT, "(debug) transaction tracking [+] n=%d\n", active_txids_.size());
			return item;
		}
	}
	logprintf(LOG_DEFAULT, "(debug) transaction tracking: allocation failed after %d retries\n", max_retry);
	return std::nullopt;
}

void Behind::release_txid(Forwarder const &forwarder, int upstream_id)
{
	TransactionID item;
	item.d->k.af_type = forwarder.af_type;
	memcpy(item.d->k.addr, forwarder.addr, sizeof(item.d->k.addr));
	item.d->k.txid = upstream_id;
	auto it = active_txids_.find(item);
	if (it != active_txids_.end()) {
		active_txids_.erase(it);
	}
	logprintf(LOG_DEFAULT, "(debug) transaction tracking [-] n=%d\n", active_txids_.size());
}

InetAddrPort InetAddrPort::parse(std::string name)
{
	InetAddrPort ret;

	auto ParsePortNumber = [](std::string const &s) {
		int v = 0;
		size_t n = misc::parse_int(s.c_str(), &v);
		if (n == s.size()) {
			if (v > 0 && v < 65536) {
				return v;
			}
		}
		return 0;
	};

	try {
		static const std::regex re_ipv4(R"---(^\s*((\d{1,3}\.){3}\d{1,3})(@(\d+))?\s*$)---");
		static const std::regex re_ipv6(R"---(^\s*(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+)(@(\d+))?\s*$)---");
		if (std::smatch m; std::regex_match(name, m, re_ipv4)) {
			name = m[1];
			if (m[4].matched) {
				ret.port = ParsePortNumber(m[4]);
			}
			struct sockaddr_in sa4 = { };
			if (inet_pton(AF_INET, name.c_str(), &sa4.sin_addr) == 1) {
				ret.addr.type = InetResolver::IN4;
				ret.addr.add_in4(&sa4.sin_addr.s_addr);
			}
		} else if (std::smatch m; std::regex_match(name, m, re_ipv6)) {
			name = m[1];
			if (name.front() == '[' && name.back() == ']') {
				name = name.substr(1, name.size() - 2);
			}
			if (m[3].matched) {
				ret.port = ParsePortNumber(m[3]);
			}
			struct sockaddr_in6 sa6 = { };
			if (inet_pton(AF_INET6, name.c_str(), &sa6.sin6_addr) == 1) {
				ret.addr.type = InetResolver::IN6;
				ret.addr.add_in6(&sa6.sin6_addr.s6_addr);
			}
		}
	} catch (std::regex_error const &e) {
		logprintf(LOG_BOTH, "address parser regular-expression error: %s\n", e.what());
		return { };
	}
	return ret;
}

void Behind::init_forwarder()
{
	for (Options::Zone const &z : m->options.forward_addr) {
		InetResolver::Addr addr;
		int port = STANDARD_DNS_PORT;

		// validate_runtime_inputs() records the exact endpoint that was checked,
		// avoiding a second DNS lookup between validation and activation. Keep the
		// parsing fallback for callers that construct Option programmatically.
		InetAddrPort addrport = z.endpoint;
		if (!addrport) addrport = InetAddrPort::parse(z.name);
		if (addrport.port > 0) {
			port = addrport.port;
		}
		InetResolver::Type type = addrport.addr.type;
		if (addrport.addr) {
			addr = addrport.addr;
		} else {
			if (!m->resolver.resolve(z.name.c_str(), type, &addr)) {
				m->forwarders_valid = false;
				logprintf(LOG_BOTH, "failed to resolve forwarder: %s\n", z.name.c_str());
			}
			type = addr.type;
		}

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

		// validate_options() rejects a non-absolute zone before we get here, but
		// fail safe rather than abort() if that ever regresses: an unusable
		// forwarder entry must not take the whole server down.
		if (z.zone.empty() || z.zone.back() != '.') {
			logprintf(LOG_BOTH, "ignoring forwarder with a non-absolute zone: %s\n", z.zone.c_str());
			continue;
		}
		forwarder.zone = z.zone;
		m->forwarders.push_back(forwarder);
	}
}

int Behind::ctl_add(int fd, struct epoll_event *e, bool in, bool out)
{
	if (fd == -1) return -1;
	int ret = 0;

	if (m->socket_mode == SocketMode::SELECT) {
		auto Add = [](std::vector<int> *fds, int fd) {
			if (std::find(fds->begin(), fds->end(), fd) == fds->end()) {
				fds->push_back(fd);
			}
		};
		if (in) Add(&m->select_in_fds, fd);
		if (out) Add(&m->select_out_fds, fd);
	}

	if (e && m->epoll_fd != -1) {
		ret = epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, e->data.fd, e);
	}
	return ret;
}

int Behind::ctl_mod(int fd, struct epoll_event *e, bool in, bool out)
{
	if (fd == -1 || !e) return -1;
	if (m->socket_mode == SocketMode::SELECT) {
		auto Set = [fd](std::vector<int> *fds, bool enabled) {
			auto found = std::find(fds->begin(), fds->end(), fd);
			if (enabled && found == fds->end()) fds->push_back(fd);
			if (!enabled && found != fds->end()) fds->erase(found);
		};
		Set(&m->select_in_fds, in);
		Set(&m->select_out_fds, out);
	}
	e->events = (in ? (uint32_t)EPOLLIN : 0U) | (out ? (uint32_t)EPOLLOUT : 0U) | EPOLLERR | EPOLLHUP;
	e->data.fd = fd;
	if (m->epoll_fd != -1) {
		return epoll_ctl(m->epoll_fd, EPOLL_CTL_MOD, fd, e);
	}
	return 0;
}

int Behind::ctl_del(int fd, struct epoll_event *e)
{
	if (fd == -1) return -1;
	int ret = 0;

	if (m->socket_mode == SocketMode::SELECT) {
		auto Remove = [](std::vector<int> *fds, int fd) {
			auto it = std::remove(fds->begin(), fds->end(), fd);
			fds->erase(it, fds->end());
		};
		Remove(&m->select_in_fds, fd);
		Remove(&m->select_out_fds, fd);
	}

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
		int upstream_fd = task->upstream_fd;
		if (task->upstream_fd != -1) {
			delete_socket(task->upstream_fd, task->ev.get());
			task->upstream_fd = -1;
		}
		if (task->client_fd != -1 && task->client_fd != upstream_fd) {
			// The accepted client TCP socket is registered in epoll under the
			// original READING_FROM_CLIENT task and is not otherwise closed once
			// forwarding starts. Release it whenever the owning task is torn down
			// (reply sent, upstream error, or timeout in clean()) so that
			// idle-after-query connections cannot leak file descriptors.
			delete_socket(task->client_fd, nullptr);
			task->client_fd = -1;
		}
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

bool Behind::is_udp_query_active(std::shared_ptr<UdpQuery> const &query) const
{
	if (!query) return false;
	auto range = m->udp_queries_by_local_txid.equal_range(query->local_transaction_id);
	for (auto it = range.first; it != range.second; ++it) {
		if (it->second == query) return true;
	}
	return false;
}

// Retire a single in-flight upstream query: release its channel slot and both
// index entries. Once the last sibling of a transaction is gone the coalescing
// entry goes too, otherwise pending_udp would keep a PendingQuery that no
// upstream query can ever complete and later clients would join it and hang.
void Behind::finish_udp_query(std::shared_ptr<UdpQuery> const &query)
{
	if (!query) return;
	if (std::shared_ptr<UdpChannel> channel = find_udp_channel_by_fd(query->channel_fd)) {
		if (channel->active_queries > 0) {
			channel->active_queries--;
		}
	}
	// Erase by (key, query) identity in both indexes. Siblings of a fanned-out
	// query share the local transaction id, so erasing by key alone would
	// unregister them too and orphan them in udp_queries_by_socket_txid, where
	// no deadline scan would ever reach them again.
	auto by_txid = m->udp_queries_by_local_txid.equal_range(query->local_transaction_id);
	for (auto it = by_txid.first; it != by_txid.second; ++it) {
		if (it->second == query) {
			m->udp_queries_by_local_txid.erase(it);
			break;
		}
	}
	auto by_socket = m->udp_queries_by_socket_txid.equal_range(udp_socket_txid_key(query->channel_fd, query->upstream_id));
	for (auto it = by_socket.first; it != by_socket.second; ++it) {
		if (it->second == query) {
			m->udp_queries_by_socket_txid.erase(it);
			break;
		}
	}
	if (query->pending && m->udp_queries_by_local_txid.count(query->local_transaction_id) == 0) {
		auto found = m->pending_udp.find(query->pending->key);
		if (found != m->pending_udp.end() && found->second == query->pending) {
			m->pending_udp.erase(found);
		}
	}

	release_txid(query->forwarder, query->upstream_id);
}

// Complete a whole client transaction: retire every sibling that was fanned out
// for it, because one has answered (first valid response wins) or all of them
// have timed out. Retiring the last sibling drops the coalescing entry.
void Behind::finish_udp_transaction(uint32_t local_transaction_id)
{
	std::vector<std::shared_ptr<UdpQuery>> siblings;
	auto range = m->udp_queries_by_local_txid.equal_range(local_transaction_id);
	for (auto it = range.first; it != range.second; ++it) {
		siblings.push_back(it->second);
	}
	for (std::shared_ptr<UdpQuery> const &query : siblings) {
		finish_udp_query(query);
	}
}

// Deadline scanning and the uptime tick are O(in-flight tasks + channels), but
// the event loop used to call them after *every* epoll_wait, i.e. once per
// datagram at low concurrency. Timeout granularity is bounded by the loop's
// interval_ms anyway, so running them at most every MAINTENANCE_INTERVAL_MS
// keeps the same behaviour and removes a full hash-table walk per query.
void Behind::periodic(InternalData *d)
{
	constexpr uint64_t MAINTENANCE_INTERVAL_MS = 100;
	uint64_t now = misc::get_tick_count();
	if (now - m->last_maintenance < MAINTENANCE_INTERVAL_MS) return;
	m->last_maintenance = now;
	uptime();
	clean(d);
}

void Behind::clean(InternalData *d)
{
	enum State {
		CLEAN_PAUSED_LISTENERS,
		CLEAN_EXPIRED_TCP,
		CLEAN_EXPIRED_UDP,
		CLEAN_ACTIVE_TXIDS,
	};

	uint64_t now = misc::get_tick_count();
	if (m->clean_state == CLEAN_PAUSED_LISTENERS) {
		for (auto it = m->paused_listeners.begin(); it != m->paused_listeners.end();) {
			if (now < it->second) {
				it++;
				continue;
			}
			InternalData::In *input = nullptr;
			if (d->in4_tcp.listener_fd == it->first)
				input = &d->in4_tcp;
			else if (d->in6_tcp.listener_fd == it->first)
				input = &d->in6_tcp;
			if (input && ctl_mod(it->first, &input->ev, true, false) == 0) {
				it = m->paused_listeners.erase(it);
			} else {
				it->second = now + 1000;
				it++;
			}
		}
	} else if (m->clean_state == CLEAN_EXPIRED_TCP) {
		std::vector<std::shared_ptr<Task>> expired;
		for (auto const &item : m->tasks_by_fd) {
			std::shared_ptr<Task> const &task = item.second;
			if (now - task->timestamp >= (uint64_t)task->timeout) {
				expired.push_back(task);
			}
		}
		for (auto const &task : expired) {
			if (!task || task->upstream_fd == -1 || find_task_by_fd(task->upstream_fd) != task) continue;
			if (task->op == Operation::FORWARD_TO_UPSTREAM_TCP || task->op == Operation::REPLY_TO_CLIENT_TCP) {
				dns::Message failure;
				failure.header.id = task->requester_id;
				failure.header.flags = 0x8182;
				dns::Question question;
				question.name = task->request_name;
				question.type = task->type;
				question.clas = task->clas;
				failure.questions = { question };
				set_edns0(&failure, task->client_udp_payload);
				if (dns::Cache *cache = get_cache(task->type)) {
					cache->insert_failure(task->forward_name, task->type, task->clas, failure);
				}
				int client_fd = task->client_fd;
				ProtocolFamilyType client_proto = task->client_proto;
				InternalData client = make_client_data(*d, client_proto, client_fd);
				finish_task(task, false);
				task->client_fd = -1;
				if (!send_dns_message(&client, client_proto, failure, false, false)) {
					delete_socket(client_fd, nullptr);
				}
				continue;
			}
			finish_task(task);
		}
	} else if (m->clean_state == CLEAN_EXPIRED_UDP) {
		std::vector<std::shared_ptr<UdpQuery>> expired_udp_queries;
		for (auto const &item : m->udp_queries_by_local_txid) {
			std::shared_ptr<UdpQuery> const &query = item.second;
			if (query && now - query->timestamp >= (uint64_t)query->timeout) {
				expired_udp_queries.push_back(query);
			}
		}
		for (std::shared_ptr<UdpQuery> const &query : expired_udp_queries) {
			// A sibling of this query may already have retired the whole transaction
			// earlier in this same loop; skip whatever is no longer registered.
			if (!is_udp_query_active(query)) continue;
			dns::Message failure;
			failure.header.flags = 0x8182;
			dns::Question question;
			question.name = query->request_name;
			question.type = query->type;
			question.clas = query->clas;
			failure.questions = { question };
			if (dns::Cache *cache = get_cache(query->type)) {
				cache->insert_failure(query->forward_name, query->type, query->clas, failure);
			}
			std::vector<PendingQuery::Waiter> waiters = query->pending ? query->pending->waiters : std::vector<PendingQuery::Waiter>();
			for (PendingQuery::Waiter const &waiter : waiters) {
				dns::Message sending = failure;
				sending.header.id = waiter.requester_id;
				sending.questions.front().name = waiter.request_name;
				set_edns0(&sending, waiter.udp_payload);
				InternalData client = *d;
				if (waiter.proto.is_inet4()) {
					client.in4_udp.sa4 = waiter.sa4;
				} else {
					client.in6_udp.sa6 = waiter.sa6;
				}
				send_dns_message(&client, waiter.proto, sending, false, false);
			}
			// Retire every sibling of the timed-out transaction, not just this one.
			finish_udp_transaction(query->local_transaction_id);
		}
	} else if (m->clean_state == CLEAN_ACTIVE_TXIDS) {
		std::unordered_set<TransactionID> new_set;
		for (TransactionID const &item : active_txids_) {
			if (now - item.d->timestamp < m->options.upstream_timeout_ms) {
				new_set.emplace(item);
			}
		}
		active_txids_ = std::move(new_set);
	} else {
		m->clean_state = 0;
		return;
	}
	m->clean_state++;
}

std::shared_ptr<Behind::Task> Behind::find_task_by_fd(int fd) const
{
	auto it = m->tasks_by_fd.find(fd);
	if (it == m->tasks_by_fd.end()) {
		return { };
	}
	return it->second;
}

void Behind::finish_task(std::shared_ptr<Task> task, bool close_client)
{
	if (!task) return;
	int fd = task->upstream_fd;
	if (fd != -1) {
		auto it = m->tasks_by_fd.find(fd);
		if (it != m->tasks_by_fd.end() && it->second == task) {
			m->tasks_by_fd.erase(it);
		}
		delete_socket(fd, task->ev.get());
		task->upstream_fd = -1;
	}
	if (close_client && task->client_fd != -1 && task->client_fd != fd) {
		delete_socket(task->client_fd, nullptr);
		task->client_fd = -1;
	}
	release_txid(task->forwarder, task->upstream_id);
}

void Behind::push_task(std::shared_ptr<Task> task, int timeout, uint32_t epoll_events)
{
	// Tasks are dispatched by their unique socket fd.  Response transaction IDs
	// are validated separately and never serve as task-map keys.
	// Evicting by upstream_id was actively harmful: READING_FROM_CLIENT tasks
	// leave upstream_id at 0 and TCP forward tasks use the client-supplied
	// header.id, so registering one connection could tear down an unrelated
	// one (a second TCP client, or a client that sent id 0).

	init_epoll_event(task.get(), task->upstream_fd, epoll_events);
	ctl_add(task->upstream_fd, task->ev.get(), (epoll_events & EPOLLIN) != 0, (epoll_events & EPOLLOUT) != 0);

	task->timestamp = misc::get_tick_count();
	task->timeout = timeout;

	m->tasks_by_fd[task->upstream_fd] = task;
}

bool Behind::parse_dns_message(const char *begin, const char *end, dns::Message *msg)
{
	if (!msg) return false;
	*msg = { };

	if (!begin || !end || begin > end || end - begin < 12) return false;

	char const *ptr = begin;

	msg->header.id = ntohs_p(ptr + 0);
	msg->header.flags = ntohs_p(ptr + 2);
	msg->header.qdcount = ntohs_p(ptr + 4);
	msg->header.ancount = ntohs_p(ptr + 6);
	msg->header.nscount = ntohs_p(ptr + 8);
	msg->header.arcount = ntohs_p(ptr + 10);
	ptr += 12;

	constexpr uint16_t MAX_SECTION_COUNT = 100;
	if (msg->header.qdcount > MAX_SECTION_COUNT || msg->header.ancount > MAX_SECTION_COUNT || msg->header.nscount > MAX_SECTION_COUNT || msg->header.arcount > MAX_SECTION_COUNT) {
		return false;
	}

	for (int i = 0; i < msg->header.qdcount; i++) {
		dns::Question q;
		int n = parse_question_section(begin, end, ptr, &q);
		if (n > 0) {
			ptr += n;
			msg->questions.push_back(q);
		} else {
			return false;
		}
	}

	bool seen_opt = false;
	auto ParseRecord = [&](uint16_t count, std::vector<dns::Record> *records, bool additional_section) {
		for (int i = 0; i < count; i++) {
			dns::Record a;
			int n = decode_name(begin, end, ptr, &a.name);
			if (n <= 0) return false;
			ptr += n;
			if (end - ptr < 10) return false;
			a.type = (DNS_TYPE)ntohs_p(ptr + 0);
			a.clas = (DNS_CLASS)ntohs_p(ptr + 2);
			a.ttl = ntohl_p(ptr + 4);
			uint16_t rdlen = ntohs_p(ptr + 8);
			ptr += 10;
			if ((size_t)(end - ptr) < rdlen) return false;
			char const *rdata_begin = ptr;
			char const *rdata_end = ptr + rdlen;

			auto DecodeRdataName = [&](std::string *out) {
				int consumed = decode_name(begin, end, ptr, out);
				if (consumed <= 0 || (size_t)(rdata_end - ptr) < (size_t)consumed) return false;
				ptr += consumed;
				return true;
			};
			auto CopyRaw = [&]() {
				a.bin.assign((uint8_t const *)rdata_begin, (uint8_t const *)rdata_end);
				ptr = rdata_end;
			};

			if (a.type == DNS_TYPE::A) {
				if (rdlen != 4) return false;
				CopyRaw();
			} else if (a.type == DNS_TYPE::AAAA) {
				if (rdlen != 16) return false;
				CopyRaw();
			} else if (a.type == DNS_TYPE::CNAME) {
				std::shared_ptr<dns::CNAME> cname = std::make_shared<dns::CNAME>();
				if (!DecodeRdataName(&cname->cname) || ptr != rdata_end) return false;
				cname->cname = misc::strtolower(cname->cname);
				a.set_cname(cname);
			} else if (a.type == DNS_TYPE::PTR) {
				std::shared_ptr<dns::PTR> p = std::make_shared<dns::PTR>();
				if (!DecodeRdataName(&p->ptr) || ptr != rdata_end) return false;
				p->ptr = misc::strtolower(p->ptr);
				a.set_ptr(p);
			} else if (a.type == DNS_TYPE::NS) {
				std::shared_ptr<dns::NS> ns = std::make_shared<dns::NS>();
				if (!DecodeRdataName(&ns->nsname) || ptr != rdata_end) return false;
				ns->nsname = misc::strtolower(ns->nsname);
				a.set_ns(ns);
			} else if (a.type == DNS_TYPE::MX) {
				if (rdlen < 3) return false; // preference plus at least the root label
				std::shared_ptr<dns::MX> mx = std::make_shared<dns::MX>();
				mx->preference = ntohs_p(ptr);
				ptr += 2;
				if (!DecodeRdataName(&mx->exchange) || ptr != rdata_end) return false;
				mx->exchange = misc::strtolower(mx->exchange);
				a.set_mx(mx);
			} else if (a.type == DNS_TYPE::SOA) {
				std::shared_ptr<dns::SOA> soa = std::make_shared<dns::SOA>();
				if (!DecodeRdataName(&soa->nname)) return false;
				if (!DecodeRdataName(&soa->rname)) return false;
				if (rdata_end - ptr != 20) return false;
				soa->serial = ntohl_p(ptr + 0);
				soa->refresh = ntohl_p(ptr + 4);
				soa->retry = ntohl_p(ptr + 8);
				soa->expire = ntohl_p(ptr + 12);
				soa->minimum = ntohl_p(ptr + 16);
				ptr += 20;
				soa->nname = misc::strtolower(soa->nname);
				soa->rname = misc::strtolower(soa->rname);
				a.set_soa(soa);
			} else if (a.type == DNS_TYPE::HTTPS) {
				if (rdlen < 3) return false; // priority plus at least the root label
				std::shared_ptr<dns::HTTPS> https = std::make_shared<dns::HTTPS>();
				https->priority = ntohs_p(ptr);
				ptr += 2;
				if (!DecodeRdataName(&https->name)) return false;
				https->name = misc::strtolower(https->name);
				bool first = true;
				uint16_t previous_key = 0;
				for (char const *p = ptr; p < rdata_end;) {
					if (rdata_end - p < 4) return false;
					uint16_t key = ntohs_p(p);
					size_t length = ntohs_p(p + 2);
					if (!first && key <= previous_key) return false;
					first = false;
					previous_key = key;
					p += 4;
					if ((size_t)(rdata_end - p) < length) return false;
					p += length;
				}
				https->data.assign(ptr, rdata_end);
				ptr = rdata_end;
				a.set_https(https);
			} else if (a.type == DNS_TYPE::TXT) {
				if (rdlen == 0) return false;
				for (char const *p = rdata_begin; p < rdata_end;) {
					size_t length = (uint8_t)*p++;
					if ((size_t)(rdata_end - p) < length) return false;
					p += length;
				}
				CopyRaw();
			} else if (a.type == DNS_TYPE::OPT) {
				// OPT is a pseudo-RR and is only valid in the Additional section with
				// the root owner name.  Its RDATA is a sequence of framed options.
				if (!additional_section || !a.name.empty() || seen_opt) return false;
				seen_opt = true;
				for (char const *p = rdata_begin; p < rdata_end;) {
					if (rdata_end - p < 4) return false;
					size_t length = ntohs_p(p + 2);
					p += 4;
					if ((size_t)(rdata_end - p) < length) return false;
					p += length;
				}
				CopyRaw();
			} else {
				// Preserve unknown RDATA.  Compression is RR-type-specific, so an
				// otherwise opaque field containing a valid backward pointer cannot be
				// safely cached/re-encoded at a different packet offset.
				for (char const *p = rdata_begin; p + 1 < rdata_end; p++) {
					uint8_t first = (uint8_t)p[0];
					if ((first & 0xc0) == 0xc0) {
						size_t offset = ((size_t)(first & 0x3f) << 8) | (uint8_t)p[1];
						if (offset < (size_t)(p - begin)) {
							a.cacheable = false;
							break;
						}
					}
				}
				CopyRaw();
			}
			if (ptr != rdata_end) return false;
			records->push_back(std::move(a));
		}
		return true;
	};
	if (!ParseRecord(msg->header.ancount, &msg->answers, false)) return false;
	if (!ParseRecord(msg->header.nscount, &msg->authorities, false)) return false;
	if (!ParseRecord(msg->header.arcount, &msg->additionals, true)) return false;
	return ptr == end;
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
			return { d->in4_udp.fd, ::addr_to_string(AF_INET, (struct sockaddr *)&d->in4_udp.sa4) };
		} else if (proto.is_inet6()) {
			return { d->in6_udp.fd, ::addr_to_string(AF_INET6, (struct sockaddr *)&d->in6_udp.sa6) };
		}
	} else if (proto.is_stream()) {
		if (proto.is_inet4()) {
			return { d->in4_tcp.fd, ::addr_to_string(AF_INET, (struct sockaddr *)&d->in4_tcp.sa4) };
		} else if (proto.is_inet6()) {
			return { d->in6_tcp.fd, ::addr_to_string(AF_INET6, (struct sockaddr *)&d->in6_tcp.sa6) };
		}
	}
	return { -1, { } };
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
		int flags = MSG_NOSIGNAL;
		auto [sock, addr_str] = sock_and_address(d, proto);
		(void)addr_str;
		if (sock != -1) {
			if (proto.is_dgram()) {
				sockaddr_storage peer = { };
				socklen_t peer_len = sizeof(peer);
				if (getpeername(sock, (sockaddr *)&peer, &peer_len) == 0) {
					return ::send(sock, buf, len, flags);
				}
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

bool Behind::is_client_allowed(sa_family_t family, void const *address) const
{
	for (ClientNetwork const &network : m->allowed_clients) {
		if (network_contains(network, family, address)) return true;
	}
	return false;
}

bool Behind::consume_rate_limit(sa_family_t family, void const *address)
{
	std::string key = client_key(family, address);
	if (key.empty()) return false;
	uint64_t now = misc::get_tick_count();
	auto Refill = [&](RateBucket *bucket) {
		if (now > bucket->updated) {
			double elapsed = (double)(now - bucket->updated) / 1000.0;
			bucket->tokens = std::min<double>(m->options.rate_limit_burst, bucket->tokens + elapsed * m->options.rate_limit_qps);
			bucket->updated = now;
		}
		bucket->last_seen = now;
	};
	Refill(&m->global_rate);
	if (m->global_rate.tokens < 1.0) {
		if (now - m->global_rate.last_limited_log >= 60000) {
			m->global_rate.last_limited_log = now;
			logprintf(LOG_DEFAULT, "global rate limit reached: dropping query from %s\n", key.c_str());
		}
		return false;
	}

	const size_t maximum_clients = std::max<size_t>(1024, m->options.max_tasks * 4);
	if (m->client_rates.size() >= maximum_clients && !m->client_rates.count(key)) {
		if (now - m->last_rate_cleanup >= 1000) {
			m->last_rate_cleanup = now;
			for (auto it = m->client_rates.begin(); it != m->client_rates.end();) {
				if (now - it->second.last_seen > 60000) {
					it = m->client_rates.erase(it);
				} else {
					it++;
				}
			}
		}
		if (m->client_rates.size() >= maximum_clients) return false;
	}

	auto [it, inserted] = m->client_rates.try_emplace(key);
	RateBucket &client = it->second;
	if (inserted) {
		client.tokens = m->options.rate_limit_burst;
		client.updated = now;
	}
	Refill(&client);
	if (client.tokens < 1.0) {
		if (now - client.last_limited_log >= 60000) {
			client.last_limited_log = now;
			logprintf(LOG_DEFAULT, "per-client rate limit reached: dropping query from %s\n", key.c_str());
		}
		return false;
	}
	m->global_rate.tokens -= 1.0;
	client.tokens -= 1.0;
	return true;
}

bool Behind::is_matching_response(std::shared_ptr<Task> task, dns::Message const &received) const
{
	if (!task) {
		return false;
	}
	if (received.header.id != task->upstream_id) {
		return false;
	}
	if ((received.header.flags & 0x8000) == 0) {
		return false;
	}
	if ((received.header.flags & 0x7800) != 0) {
		return false;
	}
	if (received.questions.size() != 1) {
		return false;
	}
	dns::Question const &q = received.questions.front();
	if (q.name != task->forward_name) {
		return false;
	}
	if (q.type != task->type || q.clas != task->clas) {
		return false;
	}
	return true;
}

bool Behind::is_cacheable_response(std::shared_ptr<Task> task, dns::Message const &received) const
{
	if (!is_matching_response(task, received) || (received.header.flags & 0x0200)) {
		return false;
	}
	uint16_t rcode = received.header.flags & 0x000f;
	if (rcode != 0 && rcode != 3) return false;
	auto RecordsAreCacheable = [](std::vector<dns::Record> const &records) {
		for (dns::Record const &record : records) {
			if (!record.cacheable || record.type == DNS_TYPE::OPT) return false;
		}
		return true;
	};
	return RecordsAreCacheable(received.answers) && RecordsAreCacheable(received.authorities);
}

bool Behind::is_matching_udp_response(std::shared_ptr<UdpQuery> const &query, dns::Message const &received) const
{
	if (!query) {
		return false;
	}
	if (received.header.id != query->upstream_id) {
		return false;
	}
	if ((received.header.flags & 0x8000) == 0) {
		return false;
	}
	if ((received.header.flags & 0x7800) != 0) {
		return false;
	}
	if (received.questions.size() != 1) {
		return false;
	}
	dns::Question const &q = received.questions.front();
	if (q.name != query->forward_name) {
		return false;
	}
	if (q.type != query->type || q.clas != query->clas) {
		return false;
	}
	return true;
}

bool Behind::is_cacheable_udp_response(std::shared_ptr<UdpQuery> const &query, dns::Message const &received) const
{
	if (!is_matching_udp_response(query, received) || (received.header.flags & 0x0200)) {
		return false;
	}
	uint16_t rcode = received.header.flags & 0x000f;
	if (rcode != 0 && rcode != 3) return false;
	auto RecordsAreCacheable = [](std::vector<dns::Record> const &records) {
		for (dns::Record const &record : records) {
			if (!record.cacheable || record.type == DNS_TYPE::OPT) return false;
		}
		return true;
	};
	return RecordsAreCacheable(received.answers) && RecordsAreCacheable(received.authorities);
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
	operator bool() const
	{
		return !buffer.empty();
	}
};

Behind::Packet Behind::make_dns_packet(dns::Message const &msg, bool tcp, uint16_t udp_limit)
{
	Packet ret;
	NameMap namemap;

	if (tcp) {
		ret.buffer.resize(2);
		namemap.set_offset(2);
	}

	auto LimitCount = [](size_t n) {
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

	size_t question_end = ret.buffer.size();

	auto WriteRecords = [&](int count, std::vector<dns::Record> const &records, std::vector<size_t> *ends) {
		for (int i = 0; i < count; i++) {
			dns::Record const &r = records[i];
			std::string name = stricmp(ret.q.name.c_str(), r.name.c_str()) == 0 ? ret.q.name : misc::strtolower(r.name);
			if (!write_dns_answer_rr(&ret.buffer, &namemap, name, r)) {
				return false;
			}
			ends->push_back(ret.buffer.size());
		}
		return true;
	};

	std::vector<size_t> answer_ends;
	std::vector<size_t> authority_ends;
	std::vector<size_t> additional_ends;

	if (!WriteRecords(h.ancount, msg.answers, &answer_ends)) {
		return { };
	}
	if (!WriteRecords(h.nscount, msg.authorities, &authority_ends)) {
		return { };
	}
	for (int i = 0; i < h.arcount; i++) {
		dns::Record const &r = msg.additionals[i];
		std::string name = r.type == DNS_TYPE::OPT ? std::string()
												   : (stricmp(ret.q.name.c_str(), r.name.c_str()) == 0
															 ? ret.q.name
															 : misc::strtolower(r.name));
		if (!write_dns_answer_rr(&ret.buffer, &namemap, name, r)) {
			return { };
		}
		additional_ends.push_back(ret.buffer.size());
	}

	if (tcp) {
		size_t len = ret.buffer.size() - namemap.offset();
		if (len > 65535) {
			return { }; // too large for DNS over TCP
		}
		write_us(ret.buffer.data(), (uint16_t)len);
	} else {
		size_t limit = std::max<size_t>(512, udp_limit);
		if (ret.buffer.size() > limit) {
			// Truncate to the last complete record boundary (or question section)
			size_t truncate_to = question_end;
			for (size_t end : answer_ends) {
				if (end > limit) break;
				truncate_to = end;
			}
			for (size_t end : authority_ends) {
				if (end > limit) break;
				truncate_to = end;
			}
			for (size_t end : additional_ends) {
				if (end > limit) break;
				truncate_to = end;
			}
			ret.buffer.resize(truncate_to);

			uint16_t flags = ntohs_p(ret.buffer.data() + 2) | 0x0200;
			write_us(ret.buffer.data() + 2, flags); // TC
			// recount sections that actually fit
			size_t fit = 0;
			for (size_t end : answer_ends) {
				if (end > truncate_to) break;
				fit++;
			}
			write_us(ret.buffer.data() + 6, (uint16_t)fit);
			fit = 0;
			for (size_t end : authority_ends) {
				if (end > truncate_to) break;
				fit++;
			}
			write_us(ret.buffer.data() + 8, (uint16_t)fit);
			fit = 0;
			for (size_t end : additional_ends) {
				if (end > truncate_to) break;
				fit++;
			}
			write_us(ret.buffer.data() + 10, (uint16_t)fit);
		}
	}

	return ret;
}

bool Behind::send_dns_message(InternalData *d, ProtocolFamilyType const &proto, dns::Message const &msg, bool forward, bool from_cache)
{
	bool tcp = proto.socktype() == SOCK_STREAM;
	uint16_t udp_limit = 512;
	if (!tcp) {
		for (dns::Record const &record : msg.additionals) {
			if (record.type == DNS_TYPE::OPT && record.name.empty()) {
				udp_limit = std::max<uint16_t>(512, (uint16_t)record.clas);
				break;
			}
		}
	}
	Packet packet = make_dns_packet(msg, tcp, udp_limit);
	if (!packet) return false;

	auto [upstream_fd, client] = sock_and_address(d, proto);
	bool ok = false;
	if (tcp) {
		if (upstream_fd == -1 || forward) return false;
		std::shared_ptr<Task> task = find_task_by_fd(upstream_fd);
		if (!task) {
			if (active_task_count() >= m->options.max_tasks) return false;
			task = make_task(Operation::WRITING_TO_CLIENT_TCP, next_local_transaction_id());
			task->upstream_fd = upstream_fd;
			task->client_proto = proto;
			task->buffer = std::move(packet.buffer);
			push_task(task, 3000, EPOLLOUT | EPOLLERR | EPOLLHUP);
		} else {
			task->op = Operation::WRITING_TO_CLIENT_TCP;
			task->buffer = std::move(packet.buffer);
			task->send_offset = 0;
			if (ctl_mod(upstream_fd, task->ev.get(), false, true) != 0) return false;
		}
		ok = true;
	} else {
		Sender sender(proto);
		ssize_t sent;
		do {
			sent = sender.send(d, packet.buffer.data(), packet.buffer.size());
		} while (sent < 0 && errno == EINTR);
		ok = sent == (ssize_t)packet.buffer.size();
	}

	// Per-query logging is the single largest CPU cost on the response path: each
	// line means a vasprintf, two std::string copies, a queue push and a write()
	// in the writer thread. Let an operator turn it off ([logging] query-log).
	if (m->options.log_queries) {
		char const *comment = from_cache ? " (from cache)" : "";
		char const *qtype = dns_type_to_string(packet.q.type);
		if (forward) {
			logprintf(LOG_DEFAULT, "F: %s\n", packet.q.name.c_str());
		} else if ((msg.header.flags & 0x000f) == 3) { // NXDOMAIN
			logprintf(LOG_DEFAULT, "R: <<%s %s NXDOMAIN>> to %s\n", packet.q.name.c_str(), qtype, client.c_str());
		} else if (msg.answers.size() > 0) {
			std::string name = misc::strtolower(packet.q.name);
			for (dns::Record const &r : msg.answers) {
				logprintf(LOG_DEFAULT, "R: <<%s %s %s>> to %s%s\n", name.c_str(), qtype, r.to_string().c_str(), client.c_str(), comment);
			}
		} else {
			logprintf(LOG_DEFAULT, "R: <<%s %s NOANSWER>> to %s%s\n", packet.q.name.c_str(), qtype, client.c_str(), comment);
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

static std::vector<std::string> split_domain_labels(std::string const &name)
{
	std::vector<std::string> labels;
	size_t start = 0;
	while (start <= name.size()) {
		size_t dot = name.find('.', start);
		if (dot == std::string::npos) {
			if (start < name.size()) {
				labels.push_back(name.substr(start));
			}
			break;
		}
		labels.push_back(name.substr(start, dot - start));
		start = dot + 1;
	}
	return labels;
}

static std::optional<InetResolver::Addr> parse_ptr_query_addr(std::string const &name)
{
	std::string loname = misc::strtolower(name);
	if (!loname.empty() && loname.back() == '.') {
		loname.pop_back();
	}
	std::vector<std::string> labels = split_domain_labels(loname);

	if (labels.size() == 6 && labels[4] == "in-addr" && labels[5] == "arpa") {
		uint8_t bytes[4] = { };
		for (size_t i = 0; i < 4; i++) {
			int v = 0;
			if (misc::parse_int(labels[i].c_str(), &v) != labels[i].size() || v < 0 || v > 255) {
				return std::nullopt;
			}
			bytes[3 - i] = (uint8_t)v;
		}
		InetResolver::Addr addr;
		addr.type = InetResolver::IN4;
		addr.addr.emplace_back(bytes, bytes + 4);
		return addr;
	}

	if (labels.size() == 34 && labels[32] == "ip6" && labels[33] == "arpa") {
		uint8_t bytes[16] = { };
		for (size_t i = 0; i < 32; i++) {
			if (labels[i].size() != 1 || !isxdigit((unsigned char)labels[i][0])) {
				return std::nullopt;
			}
			int v = isdigit((unsigned char)labels[i][0]) ? labels[i][0] - '0' : tolower((unsigned char)labels[i][0]) - 'a' + 10;
			size_t nibble = 31 - i;
			if ((nibble & 1) == 0) {
				bytes[nibble / 2] |= (uint8_t)(v << 4);
			} else {
				bytes[nibble / 2] |= (uint8_t)v;
			}
		}
		InetResolver::Addr addr;
		addr.type = InetResolver::IN6;
		addr.addr.emplace_back(bytes, bytes + 16);
		return addr;
	}

	return std::nullopt;
}

std::string Behind::find_host_name_by_addr(InetResolver::Addr const &addr) const
{
	for (Hosts const &hosts : m->hosts) {
		for (auto const &item : hosts.map_) {
			InetResolver::Addr const &candidate = item.second;
			if (candidate.type != addr.type) continue;
			for (auto const &candidate_bytes : candidate.addr) {
				for (auto const &addr_bytes : addr.addr) {
					if (candidate_bytes == addr_bytes) {
						return item.first;
					}
				}
			}
		}
	}
	return { };
}

uint32_t Behind::next_local_transaction_id()
{
	return m->local_transaction_id++;
}

std::vector<char> Behind::read(InternalData *d, ProtocolFamilyType const &proto)
{
	std::vector<char> buf;
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
			return { };
		}
		std::array<char, 65535> datagram;
		iovec iov { datagram.data(), datagram.size() };
		msghdr message { };
		message.msg_name = sa;
		message.msg_namelen = salen;
		message.msg_iov = &iov;
		message.msg_iovlen = 1;
		ssize_t len;
		do {
			len = recvmsg(sock, &message, MSG_TRUNC);
		} while (len < 0 && errno == EINTR);
		if (len > 0 && !(message.msg_flags & MSG_TRUNC) && (size_t)len <= datagram.size()) {
			return std::vector<char>(datagram.data(), datagram.data() + len);
		}
	}
	return { };
}

dns::Cache *Behind::get_cache(DNS_TYPE type)
{
	return type != DNS_TYPE::OPT && accept_dns_type(type) ? &m->dns_cache : nullptr;
}

bool Behind::accept_dns_type(DNS_TYPE t)
{
	switch (t) {
	case DNS_TYPE::A:
	case DNS_TYPE::AAAA:
	case DNS_TYPE::CNAME:
	case DNS_TYPE::HTTPS:
	case DNS_TYPE::MX:
	case DNS_TYPE::NS:
	case DNS_TYPE::OPT:
	case DNS_TYPE::PTR:
	case DNS_TYPE::SOA:
	case DNS_TYPE::TXT:
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

size_t Behind::active_task_count() const
{
	// udp_queries_by_local_txid is a multimap with one entry per in-flight
	// upstream query, so a query fanned out to N forwarders correctly counts as
	// N. Counting transactions instead would let udp-multiple-forwarding
	// over-subscribe max-tasks (and therefore the fd budget) by up to N times.
	return m->tasks_by_fd.size() + m->udp_queries_by_local_txid.size();
}

std::shared_ptr<Behind::UdpChannel> Behind::find_udp_channel(Forwarder const &forwarder) const
{
	for (std::shared_ptr<UdpChannel> const &channel : m->udp_channels) {
		if (channel && same_forwarder_endpoint(channel->forwarder, forwarder)) {
			return channel;
		}
	}
	return { };
}

std::shared_ptr<Behind::UdpChannel> Behind::choose_udp_channel(Forwarder const &forwarder) const
{
	std::shared_ptr<UdpChannel> best;
	for (std::shared_ptr<UdpChannel> const &channel : m->udp_channels) {
		if (!channel || !same_forwarder_endpoint(channel->forwarder, forwarder)) continue;
		if (!best || channel->active_queries < best->active_queries) {
			best = channel;
		}
	}
	return best;
}

std::shared_ptr<Behind::UdpChannel> Behind::find_udp_channel_by_fd(int fd) const
{
	auto it = m->udp_channels_by_fd.find(fd);
	if (it == m->udp_channels_by_fd.end()) {
		return { };
	}
	return it->second;
}

std::shared_ptr<Behind::UdpChannel> Behind::get_or_create_udp_channel(Forwarder const &forwarder)
{
	size_t existing_count = 0;
	for (std::shared_ptr<UdpChannel> const &channel : m->udp_channels) {
		if (channel && same_forwarder_endpoint(channel->forwarder, forwarder)) {
			existing_count++;
		}
	}
	if (existing_count >= BEHIND_UPSTREAM_UDP_CHANNELS_PER_FORWARDER) {
		return choose_udp_channel(forwarder);
	}
	int fd = socket(forwarder.af_type, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == INVALID_SOCKET) {
		logprintf(LOG_DEFAULT, "socket: %s\n", strerror(errno));
		return { };
	}
	if (forwarder.is_inet6()) {
		int yes = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&yes, sizeof(yes));
	}
	sockaddr_storage storage { };
	sockaddr *sa = nullptr;
	socklen_t salen = 0;
	if (forwarder.is_inet4()) {
		auto *sa4 = (sockaddr_in *)&storage;
		init_sa4(sa4, (in_addr const *)forwarder.addr, forwarder.port);
		sa = (sockaddr *)sa4;
		salen = sizeof(*sa4);
	} else if (forwarder.is_inet6()) {
		auto *sa6 = (sockaddr_in6 *)&storage;
		init_sa6(sa6, (in6_addr const *)forwarder.addr, forwarder.port);
		sa = (sockaddr *)sa6;
		salen = sizeof(*sa6);
	}
	if (!sa || connect(fd, sa, salen) != 0) {
		logprintf(LOG_DEFAULT, "connect udp: %s\n", strerror(errno));
		closesocket(fd);
		return { };
	}
	std::shared_ptr<UdpChannel> channel = std::make_shared<UdpChannel>();
	channel->proto = { forwarder.af_type, SOCK_DGRAM };
	channel->forwarder = forwarder;
	channel->fd = fd;
	*channel->ev = { };
	channel->ev->events = EPOLLIN | EPOLLERR | EPOLLHUP;
	channel->ev->data.fd = fd;
	if (ctl_add(fd, channel->ev.get(), true, false) != 0) {
		logprintf(LOG_DEFAULT, "epoll_ctl: %s\n", strerror(errno));
		closesocket(fd);
		return { };
	}
	m->udp_channels.push_back(channel);
	m->udp_channels_by_fd[fd] = channel;
	return channel;
}

void Behind::init_epoll_event(Behind::Task *task, int fd, uint32_t events)
{
	*task->ev = { };
	task->ev->events = events;
	task->ev->data.fd = fd;
}

std::string Behind::randomize_case(std::string qname)
{
	uint32_t bits = 0;
	int remaining = 0;
	for (size_t i = 0; i < qname.size(); i++) {
		if (isalpha((unsigned char)qname[i])) {
			if (remaining == 0) {
				bits = m->rng.next_u32();
				remaining = 32;
			}
			if (bits & 1) {
				qname[i] ^= 0x20;
			}
			bits >>= 1;
			remaining--;
		}
	}
	return qname;
}

void Behind::forward_udp(
	InternalData const &d,
	ProtocolFamilyType const &client_proto,
	dns::Header const &header,
	dns::Question const &question,
	uint16_t client_udp_payload,
	uint32_t local_transaction_id,
	Forwarder const &forwarder,
	std::shared_ptr<PendingQuery> const &pending)
{
	if (active_task_count() >= m->options.max_tasks) {
		logprintf(LOG_DEFAULT, "too many tasks (%zu): dropping UDP query\n", active_task_count());
		return;
	}

	std::string query_name = question.name;
	if (m->options.case_randomize) {
		query_name = randomize_case(query_name);
	}

	dns::Message sending;
	sending.header.flags = 0x0100;
	sending.questions = { question };
	sending.questions.front().name = query_name;
	std::shared_ptr<UdpChannel> channel = get_or_create_udp_channel(forwarder);
	if (!channel) return;
	uint16_t upstream_id = 0;
	if (auto opt = allocate_txid(forwarder)) {
		upstream_id = *opt;
	} else {
		logprintf(LOG_DEFAULT, "too many active UDP upstream txids on fd=%d\n", channel->fd);
		return;
	}
	sending.header.id = upstream_id;

	InternalData d2;
	if (forwarder.is_inet4()) {
		d2.in4_udp.fd = channel->fd;
	} else if (forwarder.is_inet6()) {
		d2.in6_udp.fd = channel->fd;
	}

	set_edns0(&sending, m->options.edns0_buffer_size);
	if (send_dns_message(&d2, { forwarder.af_type, SOCK_DGRAM }, sending, true, false)) {
		std::shared_ptr<UdpQuery> query = std::make_shared<UdpQuery>();
		query->timestamp = misc::get_tick_count();
		query->timeout = m->options.upstream_timeout_ms;
		query->local_transaction_id = local_transaction_id;
		query->upstream_id = upstream_id;
		query->type = question.type;
		query->clas = question.clas;
		query->client_proto = client_proto;
		query->upstream_proto = { forwarder.af_type, SOCK_DGRAM };
		query->client_udp_payload = client_udp_payload;
		query->pending = pending;
		query->request_name = question.name;
		query->forward_name = query_name;
		query->forwarder = forwarder;
		query->channel_fd = channel->fd;
		channel->active_queries++;
		// insert(), not operator[]: siblings of a fanned-out query share the local
		// transaction id and each one must stay individually registered.
		m->udp_queries_by_local_txid.insert(std::pair<uint32_t, std::shared_ptr<Behind::UdpQuery>>(local_transaction_id, query));
		m->udp_queries_by_socket_txid.insert(std::pair<uint64_t, std::shared_ptr<Behind::UdpQuery>>(udp_socket_txid_key(channel->fd, upstream_id), query));
	}
}

Behind::ConnectionStatus Behind::forward_tcp(
	InternalData *d,
	ProtocolFamilyType const &client_proto,
	int client_fd,
	uint16_t client_request_id,
	dns::Question const &question,
	uint16_t client_udp_payload,
	uint32_t local_transaction_id,
	Forwarder const &forwarder)
{
	std::shared_ptr<Task> task = make_task(Operation::FORWARD_TO_UPSTREAM_TCP, local_transaction_id);

	task->fwdata = std::make_shared<ForwardingThreadData>();
	task->fwdata->d = *d;
	task->fwdata->forwarder = forwarder;

	if (client_proto.is_inet4()) {
		task->client_sa4 = d->in4_tcp.sa4;
	} else if (client_proto.is_inet6()) {
		task->client_sa6 = d->in6_tcp.sa6;
	} else {
		return ConnectionStatus::ERROR;
	}

	task->client_fd = client_fd;
	task->requester_id = client_request_id;
	task->client_udp_payload = client_udp_payload;
	task->request_name = question.name;
	task->forward_name = m->options.case_randomize ? randomize_case(question.name) : question.name;
	task->type = question.type;
	task->clas = question.clas;
	task->client_proto = client_proto;
	task->forwarder = forwarder;

	task->fwdata->msg.header.flags = 0x0100;
	task->fwdata->msg.questions = { question };
	task->fwdata->msg.questions.front().name = task->forward_name;
	task->send_offset = 0;

	int sock = socket(task->fwdata->forwarder.af_type, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sock == INVALID_SOCKET) {
		logprintf(LOG_DEFAULT, "socket: %s\n", strerror(errno));
		return ConnectionStatus::ERROR;
	}
	auto opt = allocate_txid(forwarder);
	if (!opt) {
		logprintf(LOG_DEFAULT, "too many active upstream txids on fd=%d\n", sock);
		return ConnectionStatus::ERROR;
	}
	task->upstream_id = *opt;
	task->fwdata->msg.header.id = task->upstream_id;

	Packet upstream_packet = make_dns_packet(task->fwdata->msg, true);
	if (!upstream_packet) return ConnectionStatus::ERROR;
	task->buffer = std::move(upstream_packet.buffer);

	set_edns0(&task->fwdata->msg, m->options.edns0_buffer_size);

	ProtocolFamilyType upstream_proto = { task->fwdata->forwarder.af_type, SOCK_STREAM };
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

	ConnectionStatus ret = ConnectionStatus::ERROR;
	if (sa) {
		auto e = connect(sock, sa, salen);
		if (e == 0 || (e < 0 && errno == EINPROGRESS)) {
			task->connect_in_progress = true;
			task->upstream_proto = upstream_proto;
			task->upstream_fd = sock;
			push_task(task, m->options.upstream_timeout_ms, EPOLLOUT | EPOLLERR | EPOLLHUP);
			ret = ConnectionStatus::CONTINUE;
		} else {
			logprintf(LOG_DEFAULT, "connect: %s\n", strerror(errno));
		}
	}
	if (ret == ConnectionStatus::ERROR) {
		closesocket(sock);
	}
	return ret;
}

void Behind::set_edns0(dns::Message *msg, uint16_t payload_size, uint8_t extended_rcode)
{
	size_t i = msg->additionals.size();
	while (i > 0) {
		i--;
		if (msg->additionals[i].type == DNS_TYPE::OPT) {
			msg->additionals.erase(msg->additionals.begin() + i);
		}
	}

	if (payload_size == 0) return;
	payload_size = std::max<uint16_t>(512, std::min<uint16_t>(payload_size, m->options.edns0_buffer_size));
	const uint8_t version = 0;
	const bool dnssec_ok = false;
	const uint16_t z = 0;

	dns::Record edns0;
	edns0.type = DNS_TYPE::OPT;
	edns0.clas = (DNS_CLASS)payload_size;
	edns0.ttl = ((uint32_t)extended_rcode << 24) | ((uint32_t)version << 16) | (dnssec_ok ? 0x8000 : 0) | z;
	msg->additionals.push_back(edns0);
}

uint16_t Behind::client_edns_payload(dns::Message const &msg) const
{
	uint16_t payload = 0;
	for (dns::Record const &record : msg.additionals) {
		if (record.type != DNS_TYPE::OPT) continue;
		if (payload != 0 || !record.name.empty()) return 0;
		uint8_t version = (uint8_t)((record.ttl >> 16) & 0xff);
		if (version != 0) return 0;
		payload = std::max<uint16_t>(512, (uint16_t)record.clas);
	}
	if (payload == 0) return 0;
	return std::min<uint16_t>(payload, m->options.edns0_buffer_size);
}

bool Behind::reply_from_cache(InternalData *d, ProtocolFamilyType const &client_proto, dns::Header const &header, dns::Question const &q, uint16_t client_udp_payload)
{
	dns::Cache *cache = get_cache(q.type);
	if (cache) {
		auto item = cache->find(q.name, q.type, q.clas);
		if (item) {
			dns::Message sending;
			sending.header.id = header.id;
			sending.header.flags = item->header.flags;
			sending.questions = { q };
			sending.answers = item->answers;
			sending.authorities = item->authorities;
			set_edns0(&sending, client_udp_payload);
			send_dns_message(d, client_proto, sending, false, true);
			return true;
		}
	}
	return false;
}

bool Behind::process_local_query(InternalData *d, ProtocolFamilyType const &client_proto,
	dns::Message const &received, dns::Question const &q)
{
	uint16_t const udp_payload = client_edns_payload(received);
	// QR + RA, with RD copied from the query (RFC 1035 4.1.1: RD "is copied into
	// the response"). Synthesized answers used to hardcode their flags: filter
	// hits sent 0x8003/0x8000, which leaves RA clear so a blocked name looked
	// like it came from a non-recursive server, and hosts/PTR answers sent
	// 0x8180, which claims RD=1 even for a +norecurse query.
	uint16_t const reply_flags = 0x8080 | (received.header.flags & 0x0100);
	auto Send = [&](dns::Message *sending) {
		set_edns0(sending, udp_payload);
		return send_dns_message(d, client_proto, *sending, false, false);
	};
	auto MakeMessage = [&](uint16_t rcode) {
		dns::Message sending;
		sending.header.id = received.header.id;
		sending.header.flags = reply_flags | rcode;
		sending.questions = { q };
		sending.authorities = { dns::Record() };
		dns::Record *r = &sending.authorities.back();
		r->name = q.name;
		r->type = DNS_TYPE::SOA;
		r->clas = q.clas;
		r->ttl = 60;
		r->set_soa(fake_soa());
		return sending;
	};

	auto SendNXDOMAIN = [&]() {
		dns::Message sending = MakeMessage(3);
		Send(&sending);
	};

	auto SendNODATA = [&]() {
		dns::Message sending = MakeMessage(0);
		Send(&sending);
	};

	if (q.clas == DNS_CLASS::IN && !q.name.empty()) {
		if (!accept_dns_type(q.type)) {
			SendNODATA();
			return true;
		}
		// check known hosts
		if (q.type == DNS_TYPE::PTR) {
			auto addr = parse_ptr_query_addr(q.name);
			if (addr) {
				update_hosts_files(false);
				std::string host_name = find_host_name_by_addr(*addr);
				if (!host_name.empty()) {
					dns::Record r;
					r.name = q.name;
					r.type = DNS_TYPE::PTR;
					r.clas = q.clas;
					r.ttl = cache_min_ttl();
					std::shared_ptr<dns::PTR> p = std::make_shared<dns::PTR>();
					p->ptr = host_name;
					r.set_ptr(p);

					dns::Message sending;
					sending.header.id = received.header.id;
					sending.header.flags = reply_flags;
					sending.questions = { q };
					sending.answers = { r };
					Send(&sending);
					return true;
				}
			}
		}

		InetResolver::Addr const *addr = find_host(q.name);
		if (addr) {
			std::vector<dns::Record> rec;
			if (q.type == DNS_TYPE::A || q.type == DNS_TYPE::AAAA) {
				if ((q.type == DNS_TYPE::A && addr->type == InetResolver::IN4) || (q.type == DNS_TYPE::AAAA && addr->type == InetResolver::IN6)) {
					dns::Record r;
					r.name = q.name;
					r.type = q.type;
					r.clas = q.clas;
					r.ttl = cache_min_ttl();
					for (std::vector<uint8_t> const &a : addr->addr) {
						r.bin = a;
						rec.push_back(r);
					}
					dns::Message sending;
					sending.header.id = received.header.id;
					sending.header.flags = reply_flags;
					sending.questions = { q };
					sending.answers = rec;
					Send(&sending);
					return true;
				}
				SendNODATA();
			} else {
				// The name exists in [hosts], only this record type does not, so
				// this is NODATA. NXDOMAIN would assert the name does not exist for
				// *any* type (RFC 2308 5, RFC 8020) and a stub resolver would
				// negative-cache the whole name: a browser that asks for
				// printer1.lan HTTPS (type 65) before A would then be unable to
				// resolve it at all.
				SendNODATA();
			}
			return true;
		}

		DomainFilter::Kind const filter_kind = m->options.domain_filter.find(q.name);
		if (filter_kind == DomainFilter::NXDOMAIN) {
			SendNXDOMAIN();
			return true;
		}
		if (filter_kind == DomainFilter::NODATA) {
			SendNODATA();
			return true;
		}
		if (q.type == DNS_TYPE::AAAA && filter_kind == DomainFilter::NODATA_AAAA) {
			SendNODATA();
			return true;
		}

		return reply_from_cache(d, client_proto, received.header, q, udp_payload);
	}
	return false;
}

void Behind::process_query_udp(InternalData *d, ProtocolFamilyType const &client_proto, dns::Message const &received, dns::Question const &q)
{
	if (process_local_query(d, client_proto, received, q)) return;

	auto SendFailure = [&](char const *file, int line) {
		auto sending = dns::Message::SERVFAIL(file, line);
		sending.header.id = received.header.id;
		sending.questions = { q };
		set_edns0(&sending, client_edns_payload(received));
		send_dns_message(d, client_proto, sending, false, false);
	};

	// If the server is already busy, don't fan out to multiple forwarders
	int fanout = (active_task_count() < m->options.max_tasks / 2) ? m->options.udp_multiple_forwarding : 1;
	std::vector<Forwarder const *> forwarders = choose_forwarder(q.name, fanout);

	if (forwarders.empty()) {
		logprintf(LOG_DEFAULT, "No forwarder configured.\n");
		SendFailure(__FILE__, __LINE__);
		return;
	}

	PendingQuery::Waiter waiter;
	waiter.proto = client_proto;
	waiter.requester_id = received.header.id;
	waiter.udp_payload = client_edns_payload(received);
	waiter.request_name = q.name;
	if (client_proto.is_inet4()) {
		waiter.sa4 = d->in4_udp.sa4;
	} else {
		waiter.sa6 = d->in6_udp.sa6;
	}

	std::string key = pending_query_key(q);
	auto existing = m->pending_udp.find(key);
	if (existing != m->pending_udp.end()) {
		constexpr size_t MAX_WAITERS_PER_QUERY = 200;
		// fprintf(stderr, "--- %d\n", (int)existing->second->waiters.size());
		if (existing->second->waiters.size() >= MAX_WAITERS_PER_QUERY) {
			SendFailure(__FILE__, __LINE__);
			return;
		}
		existing->second->waiters.push_back(std::move(waiter));
		return;
	}

	const uint32_t local_transaction_id = next_local_transaction_id();
	auto pending = std::make_shared<PendingQuery>();
	pending->key = key;
	pending->transaction_id = local_transaction_id;
	pending->waiters.push_back(std::move(waiter));
	m->pending_udp[key] = pending;
	for (Forwarder const *f : forwarders) {
		forward_udp(*d, client_proto, received.header, q, client_edns_payload(received), local_transaction_id, *f, pending);
	}
	if (m->udp_queries_by_local_txid.count(local_transaction_id) == 0) {
		m->pending_udp.erase(key);
		// fprintf(stderr, "--- %d/%d\n", (int)active_task_count(), (int)m->options.max_tasks);
		SendFailure(__FILE__, __LINE__);
	}
}

Behind::InternalData Behind::make_client_data(InternalData const &d, ProtocolFamilyType const &proto, int fd) const
{
	InternalData d2 = d;
	if (proto.is_inet4()) {
		if (proto.is_dgram()) {
			d2.in4_udp.fd = fd;
		} else if (proto.is_stream()) {
			d2.in4_tcp.fd = fd;
		}
	} else if (proto.is_inet6()) {
		if (proto.is_dgram()) {
			d2.in6_udp.fd = fd;
		} else if (proto.is_stream()) {
			d2.in6_tcp.fd = fd;
		}
	}
	return d2;
}

Behind::TcpReadResult Behind::read_tcp_message(std::shared_ptr<Task> task, dns::Message *out)
{
	const size_t MAX_TCP_DNS_LEN = 65535;

	while (true) {
		if (task->recv_expected == 0) {
			// reading 2-byte length prefix
			size_t have = task->recv_buffer.size();
			if (have < 2) {
				char lenbuf[2];
				ssize_t n = recv(task->upstream_fd, lenbuf, 2 - have, 0);
				if (n > 0) {
					task->recv_buffer.insert(task->recv_buffer.end(), lenbuf, lenbuf + n);
					continue;
				} else if (n < 0 && errno == EINTR) {
					continue;
				} else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
					return TcpReadResult::ERROR;
				}
				return TcpReadResult::NEED_MORE;
			}
			uint16_t len = ntohs_p(task->recv_buffer.data());
			if (len < 12 || len > MAX_TCP_DNS_LEN) {
				return TcpReadResult::ERROR;
			}
			task->recv_expected = len;
			task->recv_buffer.clear();
			task->recv_buffer.reserve(len);
			continue;
		} else {
			size_t need = task->recv_expected - task->recv_buffer.size();
			if (need == 0) {
				if (!parse_dns_message(task->recv_buffer.data(), task->recv_buffer.data() + task->recv_buffer.size(), out)) {
					task->recv_expected = 0;
					task->recv_buffer.clear();
					return TcpReadResult::MALFORMED;
				}
				task->recv_expected = 0;
				task->recv_buffer.clear();
				return TcpReadResult::READY;
			}
			char buf[4096];
			ssize_t n = recv(task->upstream_fd, buf, std::min(need, sizeof(buf)), 0);
			if (n > 0) {
				task->recv_buffer.insert(task->recv_buffer.end(), buf, buf + n);
				continue;
			} else if (n < 0 && errno == EINTR) {
				continue;
			} else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
				return TcpReadResult::ERROR;
			}
			return TcpReadResult::NEED_MORE;
		}
	}
}

Behind::TcpWriteResult Behind::write_tcp_buffer(std::shared_ptr<Task> task)
{
	if (!task || task->upstream_fd == -1 || task->send_offset > task->buffer.size()) {
		return TcpWriteResult::ERROR;
	}
	while (task->send_offset < task->buffer.size()) {
		ssize_t n = send(task->upstream_fd, task->buffer.data() + task->send_offset, task->buffer.size() - task->send_offset, MSG_NOSIGNAL);
		if (n > 0) {
			task->send_offset += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return TcpWriteResult::NEED_MORE;
		}
		return TcpWriteResult::ERROR;
	}
	return TcpWriteResult::DONE;
}

Behind::ConnectionStatus Behind::process_query_tcp(InternalData *d, ProtocolFamilyType const &client_proto, int client_fd, dns::Message const &received, dns::Question const &q)
{
	auto d2 = make_client_data(*d, client_proto, client_fd);
	if (process_local_query(&d2, client_proto, received, q)) {
		return ConnectionStatus::CONTINUE;
	}

	std::vector<Forwarder const *> forwarders = choose_forwarder(q.name, 1);
	if (forwarders.empty()) {
		logprintf(LOG_DEFAULT, "No forwarder configured for TCP.\n");
		auto sending = dns::Message::SERVFAIL(__FILE__, __LINE__);
		sending.header.id = received.header.id;
		sending.questions = { q };
		set_edns0(&sending, client_edns_payload(received));
		return send_dns_message(&d2, client_proto, sending, false, false) ? ConnectionStatus::CONTINUE : ConnectionStatus::ERROR;
	}

	const uint32_t local_transaction_id = next_local_transaction_id();
	Forwarder const *f = forwarders.front();
	return forward_tcp(d, client_proto, client_fd, received.header.id, q, client_edns_payload(received), local_transaction_id, *f);
}

bool Behind::reply_to_client_udp(InternalData *d, std::shared_ptr<Task> task, dns::Message const &received)
{
	if (!task || received.questions.size() != 1 || received.questions.front().name != task->forward_name || received.questions.front().type != task->type || received.questions.front().clas != task->clas) return false;

	std::vector<PendingQuery::Waiter> waiters;
	if (task->pending) {
		waiters = task->pending->waiters;
	} else {
		PendingQuery::Waiter waiter;
		waiter.proto = task->client_proto;
		waiter.requester_id = task->requester_id;
		waiter.udp_payload = task->client_udp_payload;
		waiter.request_name = task->request_name;
		if (waiter.proto.is_inet4()) {
			waiter.sa4 = task->client_sa4;
		} else {
			waiter.sa6 = task->client_sa6;
		}
		waiters.push_back(std::move(waiter));
	}

	bool sent = false;
	for (PendingQuery::Waiter const &waiter : waiters) {
		auto AmendOwner = [&](std::string const &name) {
			return stricmp(task->forward_name.c_str(), name.c_str()) == 0
				? waiter.request_name
				: misc::strtolower(name);
		};
		dns::Message sending = received;
		dns::normalize_negative_ttl(&sending);
		sending.header.id = waiter.requester_id;
		for (dns::Question &question : sending.questions) {
			question.name = waiter.request_name;
		}
		for (dns::Record &record : sending.answers) {
			record.name = AmendOwner(record.name);
		}
		for (dns::Record &record : sending.authorities) {
			record.name = AmendOwner(record.name);
		}
		set_edns0(&sending, waiter.udp_payload);
		InternalData client = *d;
		if (waiter.proto.is_inet4()) {
			client.in4_udp.sa4 = waiter.sa4;
		} else {
			client.in6_udp.sa6 = waiter.sa6;
		}
		sent = send_dns_message(&client, waiter.proto, sending, false, false) || sent;
	}
	if (sent && is_cacheable_response(task, received)) {
		dns::Message cached = received;
		cached.additionals.clear();
		if (dns::Cache *cache = get_cache(task->type)) {
			cache->insert(task->forward_name, task->type, task->clas, cached);
		}
	}
	return sent;
}

bool Behind::reply_to_client_udp(InternalData *d, std::shared_ptr<UdpQuery> const &query, dns::Message const &received)
{
	if (!query || received.questions.size() != 1 || received.questions.front().name != query->forward_name || received.questions.front().type != query->type || received.questions.front().clas != query->clas) return false;
	std::vector<PendingQuery::Waiter> waiters = query->pending ? query->pending->waiters : std::vector<PendingQuery::Waiter>();
	bool sent = false;
	for (PendingQuery::Waiter const &waiter : waiters) {
		auto AmendOwner = [&](std::string const &name) {
			return stricmp(query->forward_name.c_str(), name.c_str()) == 0
				? waiter.request_name
				: misc::strtolower(name);
		};
		dns::Message sending = received;
		dns::normalize_negative_ttl(&sending);
		sending.header.id = waiter.requester_id;
		for (dns::Question &question : sending.questions) {
			question.name = waiter.request_name;
		}
		for (dns::Record &record : sending.answers) {
			record.name = AmendOwner(record.name);
		}
		for (dns::Record &record : sending.authorities) {
			record.name = AmendOwner(record.name);
		}
		set_edns0(&sending, waiter.udp_payload);
		InternalData client = *d;
		if (waiter.proto.is_inet4()) {
			client.in4_udp.sa4 = waiter.sa4;
		} else {
			client.in6_udp.sa6 = waiter.sa6;
		}
		// fprintf(stderr, "---A %d\n", query->local_transaction_id);
		sent = send_dns_message(&client, waiter.proto, sending, false, false) || sent;
	}
	if (sent) {
		if (is_cacheable_udp_response(query, received)) {
			dns::Message cached = received;
			cached.additionals.clear();
			if (dns::Cache *cache = get_cache(query->type)) {
				cache->insert(query->forward_name, query->type, query->clas, cached);
			}
		}
	}
	return sent;
}

void Behind::process_upstream_udp_channel(InternalData *d, std::shared_ptr<UdpChannel> const &channel)
{
	if (!channel) return;
	while (true) {
		std::array<char, 65535> buffer;
		iovec iov { buffer.data(), buffer.size() };
		msghdr message { };
		message.msg_iov = &iov;
		message.msg_iovlen = 1;
		ssize_t size;
		do {
			size = recvmsg(channel->fd, &message, MSG_TRUNC);
		} while (size < 0 && errno == EINTR);

		if (size < 0) {
			// Only EAGAIN/EWOULDBLOCK means "drained". Any other error must also
			// stop the loop: a sticky error such as EBADF or ENOTCONN would
			// otherwise spin here forever, so the event loop would never return
			// and clean() would never run again.
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				logprintf(LOG_DEFAULT, "recvmsg upstream udp (fd=%d): %s\n", channel->fd, strerror(errno));
			}
			return;
		}
		if (size == 0 || (message.msg_flags & MSG_TRUNC) || (size_t)size > buffer.size()) continue;
		dns::Message received;
		if (!parse_dns_message(buffer.data(), buffer.data() + size, &received)) continue;
		auto found = m->udp_queries_by_socket_txid.find(udp_socket_txid_key(channel->fd, received.header.id));
		if (found == m->udp_queries_by_socket_txid.end()) continue;
		std::shared_ptr<UdpQuery> query = found->second;
		if (!query || query->channel_fd != channel->fd || query->upstream_id != received.header.id) continue;
		// The transaction may already have been answered by a sibling forwarder.
		if (!is_udp_query_active(query)) continue;
		if (!is_matching_udp_response(query, received)) continue;

		drop_aa_flag(&received);
		uint16_t rcode = received.header.flags & 0x000f;
		if ((rcode == 1 || rcode == 4) && query->used_edns) {
			dns::Message retry;
			retry.header.flags = 0x0100;
			dns::Question question;
			question.name = query->forward_name;
			question.type = query->type;
			question.clas = query->clas;
			retry.questions = { question };
			uint16_t retry_id = 0;
			if (auto opt = allocate_txid(channel->forwarder)) {
				retry_id = *opt;
				retry.header.id = retry_id;
				InternalData upstream;
				if (query->upstream_proto.is_inet4()) {
					upstream.in4_udp.fd = channel->fd;
				} else {
					upstream.in6_udp.fd = channel->fd;
				}
				if (send_dns_message(&upstream, query->upstream_proto, retry, true, false)) {
					m->udp_queries_by_socket_txid.erase(found);
					query->upstream_id = retry_id;
					query->used_edns = false;
					query->timestamp = misc::get_tick_count();
					m->udp_queries_by_socket_txid.insert(std::pair<uint64_t, std::shared_ptr<Behind::UdpQuery>>(udp_socket_txid_key(channel->fd, retry_id), query));
					continue;
				}
			}
		}
		if (rcode != 0 && rcode != 3) {
			if (dns::Cache *cache = get_cache(query->type)) {
				cache->insert_failure(query->forward_name, query->type, query->clas, received);
			}
		}
		if (reply_to_client_udp(d, query, received)) {
			// First valid answer wins: retire this query and cancel every sibling
			// that was fanned out for the same client transaction.
			finish_udp_transaction(query->local_transaction_id);
		} else {
			// The answer could not be delivered (e.g. it could not be
			// re-serialized). Retire just this query so the remaining siblings
			// still have a chance to answer before the deadline.
			finish_udp_query(query);
		}
	}
}

void Behind::process_receive(InternalData *d, int upstream_fd)
{
	if (std::shared_ptr<UdpChannel> channel = find_udp_channel_by_fd(upstream_fd)) {
		process_upstream_udp_channel(d, channel);
		return;
	}
	std::shared_ptr<Task> task = find_task_by_fd(upstream_fd);
	if (!task) return; // stale epoll event; the fd may already have been reused
	// Behave identically with and without NDEBUG: drop the event instead of
	// aborting the daemon if the task map ever disagrees with the event fd.
	if (task->upstream_fd != upstream_fd) return;

	auto QueueTcpResponse = [&](dns::Message sending) {
		int client_fd = task->client_fd;
		ProtocolFamilyType client_proto = task->client_proto;
		if (client_fd == -1) {
			finish_task(task);
			return false;
		}
		auto d2 = make_client_data(*d, client_proto, client_fd);
		finish_task(task, false); // closes only the upstream socket
		task->client_fd = -1;
		if (!send_dns_message(&d2, client_proto, sending, false, false)) {
			delete_socket(client_fd, nullptr);
			return false;
		}
		return true;
	};
	auto QueueServfail = [&]() {
		auto sending = dns::Message::SERVFAIL(__FILE__, __LINE__);
		sending.header.id = task->requester_id;
		dns::Question q;
		q.name = task->request_name;
		q.type = task->type;
		q.clas = task->clas;
		sending.questions = { q };
		set_edns0(&sending, task->client_udp_payload);
		if (dns::Cache *cache = get_cache(task->type)) {
			cache->insert_failure(task->request_name, task->type, task->clas, sending);
		}
		return QueueTcpResponse(std::move(sending));
	};

	if (task->op == Operation::WRITING_TO_CLIENT_TCP) {
		TcpWriteResult result = write_tcp_buffer(task);
		if (result != TcpWriteResult::NEED_MORE) finish_task(task);
		return;
	}

	if (task->op == Operation::READING_FROM_CLIENT) {
		dns::Message received;
		TcpReadResult result = read_tcp_message(task, &received);
		if (result == TcpReadResult::NEED_MORE) return;
		if (result == TcpReadResult::MALFORMED) {
			dns::Message sending;
			sending.header.id = received.header.id;
			sending.header.flags = 0x8081 | (received.header.flags & 0x0100);
			auto d2 = make_client_data(*d, task->upstream_proto, task->upstream_fd);
			if (!send_dns_message(&d2, task->upstream_proto, sending, false, false)) {
				finish_task(task);
			}
			return;
		}
		if (result == TcpReadResult::ERROR || (received.header.flags & 0x8000)) {
			finish_task(task);
			return;
		}

		uint16_t error_rcode = 0;
		if ((received.header.flags & 0x7800) != 0) {
			error_rcode = 4; // NOTIMP
		} else if (received.header.qdcount != 1 || received.questions.size() != 1 || received.header.ancount != 0 || received.header.nscount != 0) {
			error_rcode = 1;
		} else if (received.questions.front().clas != DNS_CLASS::IN) {
			error_rcode = 5;
		} else if (!accept_dns_type(received.questions.front().type) || received.questions.front().type == DNS_TYPE::OPT) {
			error_rcode = 4;
		}
		size_t opt_count = 0;
		uint16_t badvers_payload = 0;
		for (dns::Record const &additional : received.additionals) {
			if (additional.type == DNS_TYPE::OPT) {
				opt_count++;
				if (!additional.name.empty()) error_rcode = 1;
				if (((additional.ttl >> 16) & 0xff) != 0) {
					badvers_payload = std::min<uint16_t>(m->options.edns0_buffer_size,
						std::max<uint16_t>(512, (uint16_t)additional.clas));
				}
			}
		}
		if (opt_count > 1) {
			error_rcode = 1;
		}
		if (badvers_payload && error_rcode == 0) {
			dns::Message sending;
			sending.header.id = received.header.id;
			sending.header.flags = 0x8080 | (received.header.flags & 0x0100);
			sending.questions = received.questions;
			set_edns0(&sending, badvers_payload, 1); // extended RCODE 1 = BADVERS
			auto d2 = make_client_data(*d, task->upstream_proto, task->upstream_fd);
			if (!send_dns_message(&d2, task->upstream_proto, sending, false, false)) {
				finish_task(task);
			}
			return;
		}

		if (error_rcode != 0) {
			dns::Message sending;
			sending.header.id = received.header.id;
			sending.header.flags = 0x8080 | (received.header.flags & 0x0100) | error_rcode;
			if (received.questions.size() == 1) sending.questions = received.questions;
			set_edns0(&sending, client_edns_payload(received));
			auto d2 = make_client_data(*d, task->upstream_proto, task->upstream_fd);
			if (!send_dns_message(&d2, task->upstream_proto, sending, false, false)) {
				finish_task(task);
			}
			return;
		}

		int client_fd = task->upstream_fd;
		InternalData client_data = *d;
		if (task->upstream_proto.is_inet4()) {
			client_data.in4_tcp.fd = client_fd;
			client_data.in4_tcp.sa4 = task->client_sa4;
		} else {
			client_data.in6_tcp.fd = client_fd;
			client_data.in6_tcp.sa6 = task->client_sa6;
		}
		ConnectionStatus status = process_query_tcp(&client_data, task->upstream_proto, client_fd, received, received.questions.front());
		if (status == ConnectionStatus::CONTINUE) {
			if (task->op == Operation::WRITING_TO_CLIENT_TCP) return;
			// Ownership of the client fd moved to the upstream TCP task.
			m->tasks_by_fd.erase(client_fd);
			ctl_del(client_fd, task->ev.get());
			task->upstream_fd = -1;
			return;
		}

		auto sending = dns::Message::SERVFAIL(__FILE__, __LINE__);
		sending.header.id = received.header.id;
		sending.questions = received.questions;
		set_edns0(&sending, client_edns_payload(received));
		auto d2 = make_client_data(*d, task->upstream_proto, client_fd);
		if (!send_dns_message(&d2, task->upstream_proto, sending, false, false)) {
			finish_task(task);
		}
		return;
	}

	if (task->op == Operation::FORWARD_TO_UPSTREAM_TCP) {
		if (task->connect_in_progress) {
			int error = 0;
			socklen_t length = sizeof(error);
			if (getsockopt(upstream_fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0) {
				QueueServfail();
				return;
			}
			task->connect_in_progress = false;
		}
		TcpWriteResult result = write_tcp_buffer(task);
		if (result == TcpWriteResult::NEED_MORE) return;
		if (result == TcpWriteResult::ERROR) {
			QueueServfail();
			return;
		}
		task->buffer.clear();
		task->send_offset = 0;
		task->op = Operation::REPLY_TO_CLIENT_TCP;
		if (ctl_mod(upstream_fd, task->ev.get(), true, false) != 0) {
			QueueServfail();
		}
		return;
	}

	if (task->op == Operation::REPLY_TO_CLIENT_TCP) {
		dns::Message received;
		TcpReadResult result = read_tcp_message(task, &received);
		if (result == TcpReadResult::NEED_MORE) return;
		if (result != TcpReadResult::READY || !is_matching_response(task, received)) {
			QueueServfail();
			return;
		}
		uint16_t upstream_rcode = received.header.flags & 0x000f;
		if ((upstream_rcode == 1 || upstream_rcode == 4) && task->used_edns && task->fwdata) {
			dns::Message retry = task->fwdata->msg;
			auto opt = allocate_txid(task->forwarder);
			if (!opt) {
				QueueServfail();
				return;
			}
			retry.header.id = *opt;
			retry.additionals.clear();
			Packet packet = make_dns_packet(retry, true);
			if (!packet) {
				QueueServfail();
				return;
			}
			task->upstream_id = retry.header.id;
			task->used_edns = false;
			task->buffer = std::move(packet.buffer);
			task->send_offset = 0;
			task->op = Operation::FORWARD_TO_UPSTREAM_TCP;
			if (ctl_mod(upstream_fd, task->ev.get(), false, true) != 0) QueueServfail();
			return;
		}
		drop_aa_flag(&received);
		auto AmendName = [&task](std::string const &name) {
			if (stricmp(task->request_name.c_str(), name.c_str()) == 0 || stricmp(task->forward_name.c_str(), name.c_str()) == 0) {
				return task->request_name;
			}
			return misc::strtolower(name);
		};
		dns::Message sending = received;
		dns::normalize_negative_ttl(&sending);
		sending.header.id = task->requester_id;
		for (dns::Question &question : sending.questions) {
			question.name = AmendName(question.name);
		}
		for (dns::Record &a : sending.answers) {
			a.name = AmendName(a.name);
			if (a.type == DNS_TYPE::CNAME && a.cname()) {
				a.cname()->cname = AmendName(a.cname()->cname);
			} else if (a.type == DNS_TYPE::SOA && a.soa()) {
				a.soa()->nname = AmendName(a.soa()->nname);
				a.soa()->rname = AmendName(a.soa()->rname);
			} else if (a.type == DNS_TYPE::HTTPS && a.https()) {
				a.https()->name = AmendName(a.https()->name);
			}
		}
		set_edns0(&sending, task->client_udp_payload);
		if (is_cacheable_response(task, received)) {
			if (dns::Cache *cache = get_cache(task->type)) {
				cache->insert(task->forward_name, task->type, task->clas, sending);
			}
		} else if ((received.header.flags & 0x000f) != 0 && (received.header.flags & 0x000f) != 3) {
			if (dns::Cache *cache = get_cache(task->type)) {
				cache->insert_failure(task->forward_name, task->type, task->clas, sending);
			}
		}
		QueueTcpResponse(std::move(sending));
		return;
	}

	finish_task(task);
}

void Behind::drop_aa_flag(dns::Message *msg)
{
	msg->header.flags &= ~0x0400;
}

void Behind::process_udp(InternalData *d, sa_family_t family)
{
	// The client listener is level-triggered, so returning after a single
	// datagram loses nothing - but it costs one epoll_wait syscall per query.
	// Drain in a bounded batch instead. The bound matters: without it one busy
	// UDP socket could starve the TCP listener and the other address family.
	constexpr int MAX_DATAGRAMS_PER_WAKEUP = 64;
	for (int i = 0; i < MAX_DATAGRAMS_PER_WAKEUP; i++) {
		if (!process_udp_datagram(d, family)) break;
	}
}

// Returns true when a datagram was consumed, i.e. the socket may hold more.
bool Behind::process_udp_datagram(InternalData *d, sa_family_t family)
{
	ProtocolFamilyType client_proto = { family, SOCK_DGRAM };

	if (client_proto.is_inet4() || client_proto.is_inet6()) {
		std::vector<char> buf;
		buf = read(d, client_proto);
		if (buf.empty()) return false; // drained (or a read error): stop the batch
		if (client_proto.is_dgram()) {
			void const *address = client_proto.is_inet4()
				? (void const *)&d->in4_udp.sa4.sin_addr
				: (void const *)&d->in6_udp.sa6.sin6_addr;
			if (!is_client_allowed(client_proto.family(), address) || !consume_rate_limit(client_proto.family(), address)) {
				return true; // silently drop unauthorized/rate-limited UDP
			}
		}
		if (buf.size() < 12) return true;

		dns::Message received;
		if (!parse_dns_message(buf.data(), buf.data() + buf.size(), &received)) {
			uint16_t request_flags = ntohs_p(buf.data() + 2);
			if ((request_flags & 0x8000) == 0) {
				dns::Message error;
				error.header.id = ntohs_p(buf.data());
				error.header.flags = 0x8081 | (request_flags & 0x0100);
				send_dns_message(d, client_proto, error, false, false);
			}
			return true;
		}
		if (received.header.flags & 0x8000) return true;

		uint16_t error_rcode = 0;
		if ((received.header.flags & 0x7800) != 0) {
			error_rcode = 4;
		} else if (received.header.qdcount != 1 || received.questions.size() != 1 || received.header.ancount != 0 || received.header.nscount != 0) {
			error_rcode = 1;
		} else if (received.questions.front().clas != DNS_CLASS::IN) {
			error_rcode = 5;
		} else if (!accept_dns_type(received.questions.front().type) || received.questions.front().type == DNS_TYPE::OPT) {
			error_rcode = 4;
		}
		size_t opt_count = 0;
		uint16_t badvers_payload = 0;
		for (dns::Record const &additional : received.additionals) {
			if (additional.type == DNS_TYPE::OPT) {
				opt_count++;
				if (!additional.name.empty()) error_rcode = 1;
				if (((additional.ttl >> 16) & 0xff) != 0) {
					badvers_payload = std::min<uint16_t>(m->options.edns0_buffer_size, std::max<uint16_t>(512, (uint16_t)additional.clas));
				}
			}
		}
		if (opt_count > 1) {
			error_rcode = 1;
		}
		if (badvers_payload && error_rcode == 0) {
			dns::Message error;
			error.header.id = received.header.id;
			error.header.flags = 0x8080 | (received.header.flags & 0x0100);
			error.questions = received.questions;
			set_edns0(&error, badvers_payload, 1);
			send_dns_message(d, client_proto, error, false, false);
			return true;
		}
		if (error_rcode) {
			dns::Message error;
			error.header.id = received.header.id;
			error.header.flags = 0x8080 | (received.header.flags & 0x0100) | error_rcode;
			if (received.questions.size() == 1) error.questions = received.questions;
			set_edns0(&error, client_edns_payload(received));
			send_dns_message(d, client_proto, error, false, false);
			return true;
		}

		// This path only ever runs for the UDP listener, so client_proto is always
		// a datagram socket here.
		process_query_udp(d, client_proto, received, received.questions.front());
		return true;
	}
	return false;
}

void Behind::process_tcp(InternalData *d, sa_family_t family)
{
	int sock = -1;
	InternalData::In *input = nullptr;
	if (family == AF_INET) {
		input = &d->in4_tcp;
		socklen_t len = sizeof(d->in4_tcp.sa4);
		sock = accept4(d->in4_tcp.listener_fd, (sockaddr *)&d->in4_tcp.sa4, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
		d->in4_tcp.fd = sock;
	} else if (family == AF_INET6) {
		input = &d->in6_tcp;
		socklen_t len = sizeof(d->in6_tcp.sa6);
		sock = accept4(d->in6_tcp.listener_fd, (sockaddr *)&d->in6_tcp.sa6, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
		d->in6_tcp.fd = sock;
	}
	if (sock == -1) {
		int error = errno;
		if (input && (error == EMFILE || error == ENFILE)) {
			int listener = input->listener_fd;
			if (!m->paused_listeners.count(listener)) {
				logprintf(LOG_BOTH, "accept paused after file-descriptor exhaustion: %s\n", strerror(error));
				ctl_mod(listener, &input->ev, false, false);
				m->paused_listeners[listener] = misc::get_tick_count() + 1000;
			}
		} else if (error != EAGAIN && error != EWOULDBLOCK && error != EINTR && error != ECONNABORTED) {
			logprintf(LOG_DEFAULT, "accept: %s\n", strerror(error));
		}
		return;
	}
	if (sock != -1) {
		void const *address = family == AF_INET
			? (void const *)&d->in4_tcp.sa4.sin_addr
			: (void const *)&d->in6_tcp.sa6.sin6_addr;
		if (!is_client_allowed(family, address) || !consume_rate_limit(family, address)) {
			closesocket(sock);
			return;
		}
		if (active_task_count() >= m->options.max_tasks) {
			logprintf(LOG_DEFAULT, "too many tasks (%zu): rejecting TCP connection\n", active_task_count());
			closesocket(sock);
			return;
		}
		std::shared_ptr<Task> task = make_task(Operation::READING_FROM_CLIENT, next_local_transaction_id());
		task->upstream_fd = sock;
		task->upstream_proto = { family, SOCK_STREAM };
		task->client_proto = task->upstream_proto;
		if (family == AF_INET) {
			task->client_sa4 = d->in4_tcp.sa4;
		} else {
			task->client_sa6 = d->in6_tcp.sa6;
		}
		push_task(task, 3000, EPOLLIN | EPOLLERR | EPOLLHUP);
	}
}

bool Behind::init_socket(void *private_in, ProtocolFamilyType proto)
{
	Behind::InternalData::In *in = static_cast<Behind::InternalData::In *>(private_in);

	int sock = socket(proto.family(), proto.socktype() | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sock == INVALID_SOCKET) {
		logprintf(LOG_DEFAULT, "socket: %s\n", strerror(errno));
		return false;
	}

	{
		int yes = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
		if (proto.is_inet6()) {
			setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&yes, sizeof(yes));
		}
	}

	auto Bind = [&](void *private_in, ProtocolFamilyType const &proto, int sock) {
		Behind::InternalData::In *in = static_cast<Behind::InternalData::In *>(private_in);
		int r = SOCKET_ERROR;
		if (proto.is_inet4()) {
			if (m->options.listen4.addr) {
				init_sa4(&in->sa4, (in_addr *)m->options.listen4.addr.to_in4(0), m->options.listen4.port);
				r = ::bind(sock, (struct sockaddr *)&in->sa4, sizeof(in->sa4));
			}
		} else {
			if (m->options.listen6.addr) {
				init_sa6((sockaddr_in6 *)&in->sa6, (in6_addr *)m->options.listen6.addr.to_in6(0), m->options.listen6.port);
				r = ::bind(sock, (struct sockaddr *)&in->sa6, sizeof(in->sa6));
			}
		}
		if (r == SOCKET_ERROR) return false;
		return true;
	};

	if (!Bind(in, proto, sock)) {
		closesocket(sock);
		return false;
	}

	char const *proto_str = nullptr;

	if (proto.is_dgram()) {
		in->fd = sock;
		proto_str = "udp";
	} else if (proto.is_stream()) {
		if (listen(sock, 5) == SOCKET_ERROR) {
			logprintf(LOG_DEFAULT, "listen: %s\n", strerror(errno));
			closesocket(sock);
			return false;
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
	if (name.empty()) return name;
	if (!suffix.empty() && suffix.back() == '.') suffix.pop_back();
	if (name.back() == '.') {
		// Hosts-file and static-host absolute names are stored in the same
		// presentation form as decoded DNS questions (without a trailing dot).
		name.pop_back();
	} else if (!suffix.empty()) {
		name = name + '.' + suffix;
	}
	return name;
}

static Hosts parse_hosts_file_data(std::string const &suffix, std::string const &path, std::string *error)
{
	Hosts hosts;
	hosts.path = path;
	auto Fail = [&](std::string const &file, int line, std::string const &message) {
		hosts.valid = false;
		if (error && error->empty()) {
			*error = file;
			if (line > 0) *error += ':' + std::to_string(line);
			*error += ": " + message;
		}
	};

	LineReader reader;
	if (!reader.open(path)) {
		Fail(reader.error_file(), reader.error_line(), reader.error_message());
		return hosts;
	}
	std::string line;
	while (reader.getline(&line)) {
		size_t comment = line.find('#');
		if (comment != std::string::npos) line.resize(comment);
		std::string_view content = misc::trimmed(line);
		if (content.empty()) continue;
		std::vector<std::string_view> words = misc::split(content);
		if (words.size() < 2) {
			Fail(reader.file(), reader.line(), "hosts entry requires an address and at least one name");
			continue;
		}
		std::string_view ip = words[0];
		InetAddrPort addrport = InetAddrPort::parse(std::string(ip));
		if (!addrport || addrport.port != 0) {
			Fail(reader.file(), reader.line(), "invalid hosts address: " + std::string(ip));
			continue;
		}
		for (size_t i = 1; i < words.size(); i++) {
			std::string name = make_host_name(std::string(words[i]), suffix);
			if (!misc::is_valid_domain(name)) {
				Fail(reader.file(), reader.line(), "invalid hosts name: " + name);
				continue;
			}
			hosts.set(name, addrport.addr);
		}
	}
	if (reader.failed()) {
		Fail(reader.error_file(), reader.error_line(), reader.error_message());
	}

	return hosts;
}

Hosts Behind::load_hosts_file(std::string const &suffix, std::string const &path)
{
	std::string error;
	Hosts hosts = parse_hosts_file_data(suffix, path, &error);
	if (!hosts.valid) logprintf(LOG_DEFAULT, "invalid hosts file: %s\n", error.c_str());
	return hosts;
}

bool Behind::validate_runtime_inputs(Options *opts, std::string const &working_directory, std::string *error)
{
	auto Fail = [&](std::string message) {
		if (error) *error = std::move(message);
		return false;
	};
	if (!opts) return Fail("configuration is not available");
	if (working_directory.empty()) return Fail("working directory must not be empty");

	InetResolver resolver;
	for (Options::Zone &zone : opts->forward_addr) {
		InetAddrPort numeric = InetAddrPort::parse(zone.name);
		if (numeric) {
			if (numeric.port == 0) numeric.port = STANDARD_DNS_PORT;
			zone.endpoint = std::move(numeric);
		} else {
			InetResolver::Addr resolved;
			if (!resolver.resolve(zone.name.c_str(), InetResolver::UNSPEC, &resolved)) {
				return Fail("cannot resolve forwarder: " + zone.name);
			}
			zone.endpoint.addr = std::move(resolved);
			zone.endpoint.port = STANDARD_DNS_PORT;
		}
	}

	for (Options::HostsFile &hosts_file : opts->hostsfiles) {
		std::string path = hosts_file.path;
		if (!path.empty() && path.front() != '/') {
			path = working_directory + (working_directory.back() == '/' ? "" : "/") + path;
		}
		struct stat before = { };
		if (stat(path.c_str(), &before) != 0 || !S_ISREG(before.st_mode)) {
			return Fail("hosts file is not accessible: " + path);
		}
		std::string detail;
		Hosts hosts = parse_hosts_file_data(hosts_file.suffix, path, &detail);
		if (!hosts.valid) return Fail("invalid hosts file: " + detail);
		struct stat after = { };
		if (stat(path.c_str(), &after) != 0 || !S_ISREG(after.st_mode) || before.st_dev != after.st_dev || before.st_ino != after.st_ino || before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec) {
			return Fail("hosts file changed during validation: " + path);
		}
		hosts.mtime = after.st_mtime;
		hosts_file.path = std::move(path);
		hosts_file.initial_data = std::move(hosts);
	}
	if (error) error->clear();
	return true;
}

void Behind::update_hosts_files(bool force)
{
	// This runs on the hot query path (find_host / PTR lookups), so throttle
	// the per-file stat() syscalls: an unforced check inspects the files at
	// most once per interval. File changes are still picked up within that
	// window via mtime. A forced check (startup / SIGHUP reload) always runs.
	if (!force) {
		constexpr uint64_t HOSTS_CHECK_INTERVAL_MS = 1000;
		uint64_t now = misc::get_tick_count();
		if (now - m->last_hosts_check < HOSTS_CHECK_INTERVAL_MS) {
			return;
		}
		m->last_hosts_check = now;
	}

	std::vector<Options::HostsFile> const &hostsfiles = m->options.hostsfiles;

	for (Options::HostsFile const &hf : hostsfiles) {

		struct stat st;
		if (stat(hf.path.c_str(), &st) != 0) {
			logprintf(LOG_DEFAULT, "cannot stat hosts file %s: %s\n", hf.path.c_str(), strerror(errno));
			if (force) m->hosts_files_valid = false;
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
			if (!hosts.valid) {
				if (force) m->hosts_files_valid = false;
				logprintf(LOG_DEFAULT, "keeping previous hosts data for %s\n", hf.path.c_str());
				continue;
			}
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
	std::vector<Options::Host> const &hosts = m->options.hosts;

	m->hosts.clear();

	for (Options::Host const &host : hosts) {
		std::string name = make_host_name(host.name, host.suffix);
		if (!name.empty()) {
			if (!misc::is_valid_domain(name)) {
				logprintf(LOG_DEFAULT, "invalid host name in hosts: %s\n", name.c_str());
				continue;
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

	bool needs_runtime_load = false;
	for (Options::HostsFile const &hosts_file : m->options.hostsfiles) {
		if (hosts_file.initial_data && hosts_file.initial_data->valid) {
			m->hosts.push_back(*hosts_file.initial_data);
		} else {
			needs_runtime_load = true;
		}
	}
	if (needs_runtime_load) {
		// Compatibility path for programmatic Option users that did not call
		// validate_runtime_inputs(). Normal CLI startup consumes the exact hosts
		// snapshot that was validated before the old SIGHUP runtime is stopped.
		update_hosts_files(true);
	} else {
		m->last_hosts_check = misc::get_tick_count();
	}
}

int ev_fd(struct epoll_event *e)
{
	return e->data.fd;
}

#include <signal.h>

std::atomic<bool> sighup_caught { false };
std::atomic<bool> sigint_caught { false };

void on_sighup(int signum)
{
	sighup_caught.store(true, std::memory_order_relaxed);
}

void on_sigint(int signum)
{
	sigint_caught.store(true, std::memory_order_relaxed);
}

bool Behind::main(std::function<bool(bool)> const &reload_requested)
{
	signal(SIGHUP, on_sighup);
	signal(SIGINT, on_sigint);
	signal(SIGPIPE, SIG_IGN);

	initialize_hosts();
	if (!m->hosts_files_valid) {
		logprintf(LOG_BOTH, "one or more hosts files are invalid\n");
		return false;
	}
	if (!m->forwarders_valid) {
		logprintf(LOG_BOTH, "one or more forwarders are invalid\n");
		return false;
	}

	m->start_time = misc::get_tick_count();

	InternalData d;
	bool socket_ok = true;
	bool has_listen4 = m->options.listen4.addr;
	bool has_listen6 = m->options.listen6.addr;
	if (!has_listen4 && !has_listen6) {
		logprintf(LOG_BOTH, "no listen address configured\n");
		return false;
	}
	if (has_listen4) {
		socket_ok = init_socket(&d.in4_udp, { AF_INET, SOCK_DGRAM }) && socket_ok;
		socket_ok = init_socket(&d.in4_tcp, { AF_INET, SOCK_STREAM }) && socket_ok;
	}
	if (has_listen6) {
		socket_ok = init_socket(&d.in6_udp, { AF_INET6, SOCK_DGRAM }) && socket_ok;
		socket_ok = init_socket(&d.in6_tcp, { AF_INET6, SOCK_STREAM }) && socket_ok;
	}
	if (!socket_ok) {
		logprintf(LOG_BOTH, "failed to initialize sockets\n");
		auto CloseIfOpen = [](int fd) { if (fd != -1) closesocket(fd); };
		CloseIfOpen(d.in4_udp.fd);
		CloseIfOpen(d.in6_udp.fd);
		CloseIfOpen(d.in4_tcp.listener_fd);
		CloseIfOpen(d.in6_tcp.listener_fd);
		return false;
	}

	m->socket_mode = SocketMode::EPOLL;

	const int interval_ms = 100;
	bool run_ok = true;
	auto ShouldStopForReload = [&]() {
		bool const requested = sighup_caught.exchange(false, std::memory_order_relaxed);
		if (!reload_requested) return requested;
		try {
			return reload_requested(requested);
		} catch (std::exception const &e) {
			logprintf(LOG_BOTH, "configuration reload validation threw an exception; keeping previous configuration: %s\n", e.what());
			return false;
		} catch (...) {
			logprintf(LOG_BOTH, "configuration reload validation threw an unknown exception; keeping previous configuration\n");
			return false;
		}
	};

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
			int selected = select(maxfd + 1, &infds, &outfds, nullptr, &tv);
			if (selected < 0) {
				if (errno == EINTR) continue;
				logprintf(LOG_BOTH, "select: %s\n", strerror(errno));
				run_ok = false;
				break;
			}

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
			periodic(&d);

			if (sigint_caught.load(std::memory_order_relaxed)) break;
			if (ShouldStopForReload()) break;
		}
	} else if (m->socket_mode == SocketMode::EPOLL) {
		logprintf(LOG_DEFAULT, "mode: EPOLL\n");

		m->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
		if (m->epoll_fd == -1) {
			logprintf(LOG_DEFAULT, "socket: %s\n", strerror(errno));
			run_ok = false;
		} else {
			auto AddEpoll = [this](Behind::InternalData::In *in, int socktype) {
				int fd = -1;
				in->ev = { };
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
						return false;
					}
				}
				return true;
			};
			bool epoll_ok = true;
			epoll_ok = AddEpoll(&d.in4_udp, SOCK_DGRAM) && epoll_ok;
			epoll_ok = AddEpoll(&d.in6_udp, SOCK_DGRAM) && epoll_ok;
			epoll_ok = AddEpoll(&d.in4_tcp, SOCK_STREAM) && epoll_ok;
			epoll_ok = AddEpoll(&d.in6_tcp, SOCK_STREAM) && epoll_ok;
			if (!epoll_ok) run_ok = false;

			while (run_ok) {
				int n = epoll_wait(m->epoll_fd, m->epoll_events.data(), m->epoll_events.size(), interval_ms);
				if (n == -1) {
					if (errno == EINTR) {
						continue;
					}
					logprintf(LOG_DEFAULT, "epoll_wait: %s\n", strerror(errno));
					run_ok = false;
					break;
				}
				for (int i = 0; i < n; i++) {
					auto fd = m->epoll_events[i].data.fd;
					// A daemon must not die because one packet caused an
					// exception (std::bad_alloc from a large resize, or anything
					// escaping the DNS codec). Drop the offending event and keep
					// serving; std::terminate() here would abort the server.
					try {
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
					} catch (std::exception const &e) {
						logprintf(LOG_BOTH, "dropped event on fd=%d after exception: %s\n", fd, e.what());
					} catch (...) {
						logprintf(LOG_BOTH, "dropped event on fd=%d after unknown exception\n", fd);
					}
				}
				try {
					periodic(&d);
				} catch (std::exception const &e) {
					logprintf(LOG_BOTH, "periodic maintenance failed: %s\n", e.what());
				} catch (...) {
					logprintf(LOG_BOTH, "periodic maintenance failed: unknown exception\n");
				}

				if (sigint_caught.load(std::memory_order_relaxed)) break;
				if (ShouldStopForReload()) break;
			}
			::close(m->epoll_fd);
			m->epoll_fd = -1;
		}
	}

	// Close every active task before the tracked listeners.  In particular,
	// an upstream TCP task owns a detached accepted-client fd which is not in
	// the epoll/select vectors while the upstream request is in flight.
	std::vector<std::shared_ptr<Task>> active_tasks;
	for (auto const &item : m->tasks_by_fd) {
		active_tasks.push_back(item.second);
	}
	for (auto const &task : active_tasks) {
		finish_task(task);
	}

	// The descriptor tracking vectors reflect epoll interest, not ownership: a
	// TCP listener is deliberately removed from them while accept() is paused
	// after EMFILE/ENFILE.  Include the canonical InternalData descriptors and
	// de-duplicate everything so a SIGHUP during that pause cannot leak a
	// listener and make the replacement configuration fail to bind.
	std::unordered_set<int> sockets_to_close;
	auto Track = [&](int fd) { if (fd != -1) sockets_to_close.insert(fd); };
	for (int fd : m->select_in_fds) {
		Track(fd);
	}
	for (int fd : m->select_out_fds) {
		Track(fd);
	}
	Track(d.in4_udp.fd);
	Track(d.in6_udp.fd);
	Track(d.in4_tcp.listener_fd);
	Track(d.in6_tcp.listener_fd);
	for (std::shared_ptr<UdpChannel> const &channel : m->udp_channels) {
		if (channel) Track(channel->fd);
	}
	for (int fd : sockets_to_close) {
		closesocket(fd);
	}
	m->select_in_fds.clear();
	m->select_out_fds.clear();
	m->paused_listeners.clear();
	m->udp_channels.clear();
	m->udp_channels_by_fd.clear();
	m->udp_queries_by_local_txid.clear();
	m->udp_queries_by_socket_txid.clear();
	return run_ok;
}

// self test

#define EXPECT_EQ(a, b) assert((a) == (b))

std::string to_string(std::vector<uint8_t> const &buf)
{
	if (buf.empty()) {
		return std::string();
	}
	return std::string((char const *)buf.data(), buf.size());
}

static bool load_testcase(char const *file, std::vector<char> *buf)
{
	if (readfile(file, buf) && !buf->empty()) return true;
#if 0
	self_test_failures++;
	logprintf(LOG_DEFAULT, "self-test failed: cannot read fixture %s"
						" (run from the directory that contains testcase/)\n",
		file);
#endif
	return false;
}

void Behind::self_test()
{
	// host-name qualification test
	{
		EXPECT_EQ(make_host_name("relative", "lan"), "relative.lan");
		EXPECT_EQ(make_host_name("relative", "lan."), "relative.lan");
		EXPECT_EQ(make_host_name("absolute.example.", "lan"), "absolute.example");
	}

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

		in = "\x03"
			 "www"
			 "\x06"
			 "google"
			 "\x03"
			 "com"
			 "\x00";
		r = decode_name(in.data(), in.data() + 16, in.data(), &out);
		EXPECT_EQ(r, 16);
		EXPECT_EQ(out, "www.google.com");

		in = "\x03"
			 "www"
			 "\x06"
			 "google"
			 "\x03"
			 "com"
			 "\x00\x00\x00";
		r = decode_name(in.data(), in.data() + 18, in.data(), &out);
		EXPECT_EQ(r, 16);
		EXPECT_EQ(out, "www.google.com");

		in = "\x03"
			 "www"
			 "\x00\x00\x00";
		r = decode_name(in.data(), in.data() + 7, in.data(), &out);
		EXPECT_EQ(r, 5);
		EXPECT_EQ(out, "www");

		in = "\xc0\x00"; // infinite loop
		r = decode_name(in.data(), in.data() + 2, in.data(), &out);
		EXPECT_EQ(r, 0);
		EXPECT_EQ(out, "");

		in = "\x03"
			 "www"
			 "\x06"
			 "google"
			 "\x03"
			 "com"
			 "\xc0\x00"; // infinite loop
		r = decode_name(in.data(), in.data() + 17, in.data(), &out);
		EXPECT_EQ(r, 0);
		EXPECT_EQ(out, "");
	}

	// decode_name out-of-bounds read test (guard page)
	//
	// A malformed name whose label length claims more bytes than remain in
	// the message must not read past the end of the input buffer. We place a
	// single length byte (0x3f = 63) at the very last readable byte before a
	// PROT_NONE guard page. In current code decode_name advances past the
	// length byte and memcpy()s 63 bytes from the guard page, causing SIGSEGV.
	// Once the source bound is checked, decode_name must return 0 safely.
	{
		long page = sysconf(_SC_PAGESIZE);
		if (page > 0) {
			size_t pagesize = (size_t)page;
			char *base = (char *)mmap(nullptr, pagesize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (base != MAP_FAILED) {
				// make the second page inaccessible
				if (mprotect(base + pagesize, pagesize, PROT_NONE) == 0) {
					char *lenbyte = base + pagesize - 1; // last readable byte
					*lenbyte = 0x3f; // label length 63, but no data follows before the guard page
					std::string out;
					char const *begin = lenbyte;
					char const *ptr = lenbyte;
					char const *end = lenbyte + 2; // extends into the guard page; only used as a bound, never dereferenced
					int r = decode_name(begin, end, ptr, &out);
					EXPECT_EQ(r, 0);
					EXPECT_EQ(out, "");
				}
				munmap(base, pagesize * 2);
			}
		}
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

	// PTR serializer/deserializer test

	{
		dns::Message msg;
		msg.header.flags = 0x8180;
		dns::Question q;
		q.name = "1.0.0.127.in-addr.arpa";
		q.type = DNS_TYPE::PTR;
		q.clas = DNS_CLASS::IN;
		msg.questions.push_back(q);

		dns::Record r;
		r.name = q.name;
		r.type = DNS_TYPE::PTR;
		r.clas = DNS_CLASS::IN;
		r.ttl = 60;
		std::shared_ptr<dns::PTR> ptr = std::make_shared<dns::PTR>();
		ptr->ptr = "localhost";
		r.set_ptr(ptr);
		msg.answers.push_back(r);

		Packet response = make_dns_packet(msg, false);
		EXPECT_EQ(bool(response), true);

		dns::Message msg2;
		EXPECT_EQ(parse_dns_message(response.buffer.data(), response.buffer.data() + response.buffer.size(), &msg2), true);
		EXPECT_EQ(msg2.questions.size(), 1);
		EXPECT_EQ(msg2.answers.size(), 1);
		EXPECT_EQ(msg2.questions[0].type, DNS_TYPE::PTR);
		EXPECT_EQ(msg2.answers[0].type, DNS_TYPE::PTR);
		EXPECT_EQ(msg2.answers[0].ptr()->ptr, "localhost");
	}

	// malformed PTR RDATA must not read past rdlen

	{
		std::vector<char> bad;
		NameMap namemap;
		dns::Header h;
		h.flags = 0x8180;
		h.qdcount = 1;
		h.ancount = 1;
		write_dns_header(&bad, h);
		write_dns_question_rr(&bad, &namemap, "1.0.0.127.in-addr.arpa", DNS_TYPE::PTR, DNS_CLASS::IN);
		write_name(&bad, &namemap, "1.0.0.127.in-addr.arpa");
		write_us(&bad, (uint16_t)DNS_TYPE::PTR);
		write_us(&bad, (uint16_t)DNS_CLASS::IN);
		write_ul(&bad, 60);
		write_us(&bad, 2); // rdata claims only two bytes
		write(&bad, '\x01');
		write(&bad, 'a');
		write(&bad, '\x00'); // decode_name would need this byte, but it is outside rdlen

		dns::Message msg;
		EXPECT_EQ(parse_dns_message(bad.data(), bad.data() + bad.size(), &msg), false);
	}

	// DNS codec boundary and canonical-name tests
	{
		std::string out;
		std::string embedded_dot("\x03"
								 "a.b"
								 "\x00",
			5);
		std::string embedded_nul("\x03"
								 "a\x00"
								 "b\x00",
			5);
		std::string embedded_control("\x03"
									 "a\x1f"
									 "b\x00",
			5);
		std::string embedded_del("\x03"
								 "a\x7f"
								 "b\x00",
			5);
		EXPECT_EQ(decode_name(embedded_dot.data(), embedded_dot.data() + embedded_dot.size(), embedded_dot.data(), &out), 0);
		EXPECT_EQ(decode_name(embedded_nul.data(), embedded_nul.data() + embedded_nul.size(), embedded_nul.data(), &out), 0);
		EXPECT_EQ(decode_name(embedded_control.data(), embedded_control.data() + embedded_control.size(), embedded_control.data(), &out), 0);
		EXPECT_EQ(decode_name(embedded_del.data(), embedded_del.data() + embedded_del.size(), embedded_del.data(), &out), 0);

		std::vector<char> encoded;
		NameMap names;
		EXPECT_EQ(write_name(&encoded, &names, std::string("a\x00"
														   "b",
												   3)),
			false);
		EXPECT_EQ(write_name(&encoded, &names, "a..b"), false);

		// A compression pointer has only 14 offset bits.  An existing suffix
		// beyond that range must be ignored and encoded literally.
		encoded.assign(0x4000, 0);
		NameMap far_names;
		far_names.set("example.com", 0x4000);
		size_t old_size = encoded.size();
		EXPECT_EQ(write_name(&encoded, &far_names, "example.com"), true);
		EXPECT_EQ((uint8_t)encoded[old_size], 7);
	}

	// Strict RDATA framing and exact message consumption
	{
		auto MakeAnswerPacket = [&](DNS_TYPE type, std::vector<uint8_t> const &rdata) {
			std::vector<char> packet;
			NameMap names;
			dns::Header h;
			h.flags = 0x8180;
			h.qdcount = 1;
			h.ancount = 1;
			write_dns_header(&packet, h);
			write_dns_question_rr(&packet, &names, "example.com", DNS_TYPE::A, DNS_CLASS::IN);
			write_name(&packet, &names, "example.com");
			write_us(&packet, (uint16_t)type);
			write_us(&packet, (uint16_t)DNS_CLASS::IN);
			write_ul(&packet, 60);
			write_us(&packet, (uint16_t)rdata.size());
			write(&packet, (char const *)rdata.data(), (int)rdata.size());
			return packet;
		};

		dns::Message parsed;
		std::vector<char> malformed_a = MakeAnswerPacket(DNS_TYPE::A, { 127, 0, 0 });
		EXPECT_EQ(parse_dns_message(malformed_a.data(), malformed_a.data() + malformed_a.size(), &parsed), false);

		// MX target is the root label, followed by an illegal extra byte.
		std::vector<char> malformed_mx = MakeAnswerPacket(DNS_TYPE::MX, { 0, 10, 0, 0 });
		EXPECT_EQ(parse_dns_message(malformed_mx.data(), malformed_mx.data() + malformed_mx.size(), &parsed), false);

		std::vector<char> valid_a = MakeAnswerPacket(DNS_TYPE::A, { 127, 0, 0, 1 });
		EXPECT_EQ(parse_dns_message(valid_a.data(), valid_a.data() + valid_a.size(), &parsed), true);
		valid_a.push_back(0); // unaccounted trailing data is not a DNS section
		EXPECT_EQ(parse_dns_message(valid_a.data(), valid_a.data() + valid_a.size(), &parsed), false);
	}

	// Additional/unknown RR preservation and safe re-encoding
	{
		dns::Message msg;
		msg.header.flags = 0x8180;
		dns::Question q;
		q.name = "example.com";
		q.type = DNS_TYPE::A;
		q.clas = DNS_CLASS::IN;
		msg.questions.push_back(q);

		dns::Record opt;
		opt.name.clear();
		opt.type = DNS_TYPE::OPT;
		opt.clas = (DNS_CLASS)1232;
		opt.ttl = 0;
		opt.bin = { 0, 12, 0, 1, 42 };
		msg.additionals.push_back(opt);

		dns::Record unknown;
		unknown.name = q.name;
		unknown.type = (DNS_TYPE)65280;
		unknown.clas = DNS_CLASS::IN;
		unknown.ttl = 60;
		unknown.bin = { 1, 2, 3, 4 };
		msg.answers.push_back(unknown);

		Packet packet = make_dns_packet(msg, false);
		EXPECT_EQ(bool(packet), true);
		dns::Message parsed;
		EXPECT_EQ(parse_dns_message(packet.buffer.data(), packet.buffer.data() + packet.buffer.size(), &parsed), true);
		EXPECT_EQ(parsed.answers.size(), 1);
		EXPECT_EQ(parsed.answers[0].bin, unknown.bin);
		EXPECT_EQ(parsed.answers[0].cacheable, true);
		EXPECT_EQ(parsed.additionals.size(), 1);
		EXPECT_EQ(parsed.additionals[0].bin, opt.bin);
		EXPECT_EQ(bool(make_dns_packet(parsed, false)), true);

		// A pointer-looking unknown RDATA refers to the original packet layout.
		// It is retained for inspection but must not enter/rebuild from cache.
		msg.answers[0].bin = { 0xc0, 0x0c };
		packet = make_dns_packet(msg, false);
		EXPECT_EQ(bool(packet), true);
		EXPECT_EQ(parse_dns_message(packet.buffer.data(), packet.buffer.data() + packet.buffer.size(), &parsed), true);
		EXPECT_EQ(parsed.answers[0].bin, msg.answers[0].bin);
		EXPECT_EQ(parsed.answers[0].cacheable, false);
		EXPECT_EQ(bool(make_dns_packet(parsed, false)), false);

		msg.additionals.clear();
		msg.answers[0].bin.assign((size_t)UINT16_MAX + 1, 0);
		EXPECT_EQ(bool(make_dns_packet(msg, false)), false);
	}

	// serializer/desirializer test

	std::vector<char> buf;
	char const *file;

	file = "testcase/google_response.bin";
	if (load_testcase(file, &buf)) {
		dns::Message msg;
		char const *begin = buf.data();
		char const *end = begin + buf.size();
		EXPECT_EQ(parse_dns_message(begin, end, &msg), true);
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
			EXPECT_EQ(parse_dns_message(begin, end, &msg2), true);

			EXPECT_EQ(msg2.header.flags, 0x8180);
			EXPECT_EQ(msg2.header.ancount, 1);
			EXPECT_EQ(msg2.header.qdcount, 1);

			EXPECT_EQ(msg.questions, msg2.questions);
			EXPECT_EQ(msg.answers, msg2.answers);
		}
	}

	file = "testcase/amazon_response.bin";
	if (load_testcase(file, &buf)) {
		dns::Message msg;
		char const *begin = buf.data();
		char const *end = begin + buf.size();
		EXPECT_EQ(parse_dns_message(begin, end, &msg), true);
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
			EXPECT_EQ(parse_dns_message(begin, end, &msg2), true);

			EXPECT_EQ(msg2.header.flags, 0x8180);
			EXPECT_EQ(msg2.header.ancount, 3);
			EXPECT_EQ(msg2.header.qdcount, 1);

			EXPECT_EQ(msg.questions, msg2.questions);
			EXPECT_EQ(msg.answers, msg2.answers);
		}
	}

	file = "testcase/doubleclick_response.bin";
	if (load_testcase(file, &buf)) {
		dns::Message msg;
		char const *begin = buf.data();
		char const *end = begin + buf.size();
		EXPECT_EQ(parse_dns_message(begin, end, &msg), true);
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
#if 0
	logprintf(LOG_DEFAULT, "self-test: %zu checks, %zu failures\n", self_test_checks, self_test_failures);
#endif
}
