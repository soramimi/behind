#ifndef BEHIND_H
#define BEHIND_H

#include "DomainFilter.h"
#include "RandomNumberGenerator.h"
#include "inetresolver.h"
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unordered_map>
#include <unordered_set>

#define STANDARD_DNS_PORT 53
#define DEFAUT_LISTEN_PORT 5300

struct InetAddrPort {
	InetResolver::Addr addr;
	uint16_t port = 0;
	operator bool() const
	{
		return addr.type != InetResolver::UNSPEC;
	}
	static InetAddrPort parse(std::string name);
};

class ProtocolFamilyType {
private:
	sa_family_t af_family_ = AF_UNSPEC;
	int sock_type_ = SOCK_DGRAM;
	
public:
	ProtocolFamilyType() = default;
	ProtocolFamilyType(sa_family_t af_family, int sock_type)
		: af_family_(af_family)
		, sock_type_(sock_type)
	{
	}
	sa_family_t family() const
	{
		return af_family_;
	}
	int socktype() const
	{
		return sock_type_;
	}
	bool is_inet4() const
	{
		return af_family_ == AF_INET;
	}
	bool is_inet6() const
	{
		return af_family_ == AF_INET6;
	}
	bool is_dgram() const
	{
		return sock_type_ == SOCK_DGRAM;
	}
	bool is_stream() const
	{
		return sock_type_ == SOCK_STREAM;
	}
	friend bool operator==(const ProtocolFamilyType &l, const ProtocolFamilyType &r);
};
inline bool operator==(const ProtocolFamilyType &l, const ProtocolFamilyType &r)
{
	return l.af_family_ == r.af_family_ && l.sock_type_ == r.sock_type_;
}

class Hosts {
private:
public:
	bool valid = true;
	std::string path;
	time_t mtime = 0;
	std::unordered_map<std::string, InetResolver::Addr> map_;
	InetResolver::Addr const *find(std::string const &name) const;
	void set(std::string const &name, InetResolver::Addr const &addr);
	
	void clear()
	{
		map_.clear();
	}
};

struct Options {
	int listen_port = DEFAUT_LISTEN_PORT;
	InetAddrPort listen4;
	InetAddrPort listen6;
	std::string working_dir = "/var/lib/behind";
	std::string log_file = "/var/log/behind/behind.log";
	// Log one line per answered query. Defaults to on to keep the historical
	// behaviour; turning it off is the single biggest CPU saving at high QPS.
	bool log_queries = true;
	struct Zone {
		std::string zone;
		std::string name;
		InetAddrPort endpoint;
	};
	std::vector<Zone> forward_addr;
	bool case_randomize = true; // always true
	DomainFilter domain_filter;
	struct Host {
		std::string name;
		std::string suffix;
		std::string address;
	};
	std::vector<Host> hosts;
	struct HostsFile {
		std::string suffix;
		std::string path;
		std::optional<Hosts> initial_data;
	};
	std::vector<HostsFile> hostsfiles;
	// resource limits and security tuning
	size_t max_tasks = 500;
	size_t max_cache_entry_size = 65535;
	size_t max_cache_bytes = 64 * 1024 * 1024;
	uint32_t max_ttl = 86400;
	uint16_t edns0_buffer_size = 1232;
	std::vector<std::string> allow_clients;
	uint32_t rate_limit_qps = 1000;
	uint32_t rate_limit_burst = 2000;
	uint32_t upstream_timeout_ms = 3000;
	//
	int udp_multiple_forwarding = 2;
};

enum class DNS_CLASS : uint16_t {
	IN = 1,
};

enum class DNS_TYPE : uint16_t {
	A = 1,
	NS = 2,
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	MX = 15,
	TXT = 16,
	AAAA = 28,
	OPT = 41,
	HTTPS = 65,
};
char const *dns_type_to_string(DNS_TYPE type);

struct Forwarder {
	std::string zone;
	sa_family_t af_type = AF_UNSPEC;
	uint8_t addr[16] = { 0 };
	int port = STANDARD_DNS_PORT;
	operator bool() const
	{
		return af_type != AF_UNSPEC;
	}
	bool is_inet4() const
	{
		return af_type == AF_INET;
	}
	bool is_inet6() const
	{
		return af_type == AF_INET6;
	}
};

namespace dns {
struct Header;
struct Question;
struct Record;
struct Cache;
struct Message;
}

class Behind {
public:
	struct InternalData;
	
private:
	struct Private;
	Private *m;
	
	enum class Operation {
		NONE,
		READING_FROM_CLIENT,
		WRITING_TO_CLIENT_TCP,
		REPLY_TO_CLIENT_TCP,
		FORWARD_TO_UPSTREAM_TCP,
	};
	
	struct Task;
	struct PendingQuery;
	struct ForwardingThreadData;
	struct UdpChannel;
	struct UdpQuery;
	
	enum class SocketMode {
		SELECT,
		EPOLL,
	};
	
private:
	static inline bool eqi(std::string const &l, std::string const &r);
	uint16_t listen_port() const;
	int cache_min_ttl() const
	{
		return 10;
	}
	static void write(std::vector<char> *out, char c);
	static void write(std::vector<char> *out, char const *src, int len);
	static void write_us(std::vector<char> *out, uint16_t v);
	static void write_ul(std::vector<char> *out, uint32_t v);
	static void write_us(void *out, uint16_t v);
	static void write_ul(void *out, uint32_t v);
	class NameMap {
	private:
		size_t offset_ = 0;
		std::map<std::string, size_t> map_;
		
	public:
		void set_offset(size_t offset)
		{
			offset_ = offset;
		}
		size_t offset() const
		{
			return offset_;
		}
		std::map<std::string, size_t>::iterator find(std::string const &name)
		{
			return map_.find(name);
		}
		std::map<std::string, size_t>::iterator end()
		{
			return map_.end();
		}
		void set(std::string const &key, size_t val)
		{
			map_[key] = val > offset_ ? val - offset_ : 0;
		}
	};
	static bool write_name(std::vector<char> *out, NameMap *namemap, std::string const &name);
	static int decode_name(char const *begin, char const *end, char const *ptr, std::string *name);
	static void write_dns_header(std::vector<char> *out, const dns::Header &h);
	static void write_dns_question_rr(std::vector<char> *out, NameMap *namemap, std::string const &name, DNS_TYPE type, DNS_CLASS clas);
	static bool write_dns_answer_rr(std::vector<char> *out, NameMap *namemap, std::string const &name, dns::Record const &item);
	static int parse_question_section(char const *begin, char const *end, char const *ptr, dns::Question *out);
	std::vector<const Forwarder *> choose_forwarder(const std::string &name, size_t max) const;
	void init_forwarder();
	void periodic(InternalData *d);
	void clean(InternalData *d);
	size_t active_task_count() const;
	void push_task(std::shared_ptr<Task> task, int timeout, uint32_t epoll_events);
	void finish_task(std::shared_ptr<Task> task, bool close_client = true);
	bool is_udp_query_active(std::shared_ptr<UdpQuery> const &query) const;
	void finish_udp_query(std::shared_ptr<UdpQuery> const &query);
	void finish_udp_transaction(uint32_t local_transaction_id);
	static bool parse_dns_message(char const *begin, char const *end, dns::Message *msg);

	bool is_matching_response(std::shared_ptr<Task> task, dns::Message const &received) const;
	bool is_cacheable_response(std::shared_ptr<Task> task, dns::Message const &received) const;
	
	struct Packet;
	static Packet make_dns_packet(dns::Message const &msg, bool tcp, uint16_t udp_limit = 512);
	bool send_dns_message(InternalData *d, const ProtocolFamilyType &proto, dns::Message const &msg, bool forward, bool from_cache);
	void set_edns0(dns::Message *msg, uint16_t payload_size, uint8_t extended_rcode = 0);
	uint16_t client_edns_payload(dns::Message const &msg) const;
	
	enum class ConnectionStatus {
		ERROR,
		DONE,
		CONTINUE,
	};
	
	enum class TcpReadResult {
		READY,
		NEED_MORE,
		MALFORMED,
		ERROR,
	};
	enum class TcpWriteResult {
		DONE,
		NEED_MORE,
		ERROR,
	};
	
	InternalData make_client_data(InternalData const &d, ProtocolFamilyType const &proto, int fd) const;
	TcpReadResult read_tcp_message(std::shared_ptr<Task> task, dns::Message *out);
	TcpWriteResult write_tcp_buffer(std::shared_ptr<Task> task);
	
	void process_udp(InternalData *d, sa_family_t family);
	bool process_udp_datagram(InternalData *d, sa_family_t family);
	void process_tcp(InternalData *d, sa_family_t family);
	
	bool init_socket(void *private_in, ProtocolFamilyType proto);
	
	const InetResolver::Addr *find_host(std::string const &name);
	std::string find_host_name_by_addr(InetResolver::Addr const &addr) const;
	void initialize_hosts();
	uint32_t next_local_transaction_id();
	int ctl_add(int fd, epoll_event *e, bool in, bool out);
	int ctl_mod(int fd, epoll_event *e, bool in, bool out);
	int ctl_del(int fd, epoll_event *e);
	void delete_socket(int fd, struct epoll_event *e);
	void delete_socket(std::shared_ptr<Task> task);
	bool accept_dns_type(DNS_TYPE t);
	
	ConnectionStatus forward_tcp(InternalData *d,
								 const ProtocolFamilyType &client_proto,
								 int client_fd,
								 uint16_t client_request_id,
								 const dns::Question &question,
								 uint16_t client_udp_payload,
								 uint32_t local_transaction_id,
								 const Forwarder &forwarder);
	void forward_udp(const InternalData &d,
					 const ProtocolFamilyType &proto,
					 const dns::Header &header,
					 const dns::Question &q,
					 uint16_t client_udp_payload,
					 uint32_t local_transaction_id,
					 const Forwarder &forwarder,
					 std::shared_ptr<PendingQuery>
					 const &pending);
	
	std::vector<char> read(InternalData *d, const ProtocolFamilyType &proto);
	dns::Cache *get_cache(DNS_TYPE type);
	bool process_local_query(InternalData *d, const ProtocolFamilyType &client_proto, const dns::Message &received, const dns::Question &q);
	void process_query_udp(InternalData *d, const ProtocolFamilyType &proto, const dns::Message &received, const dns::Question &question);
	ConnectionStatus process_query_tcp(InternalData *d, const ProtocolFamilyType &client_proto, int client_fd, const dns::Message &received, const dns::Question &q);
	uint16_t next_txid();
	std::shared_ptr<UdpChannel> find_udp_channel(const Forwarder &forwarder) const;
	std::shared_ptr<UdpChannel> find_udp_channel_by_fd(int fd) const;
	std::shared_ptr<UdpChannel> choose_udp_channel(const Forwarder &forwarder) const;
	std::shared_ptr<UdpChannel> get_or_create_udp_channel(const Forwarder &forwarder);
	bool allocate_udp_upstream_id(int fd, uint16_t *out);
	bool is_matching_udp_response(std::shared_ptr<UdpQuery> const &query, const dns::Message &received) const;
	bool is_cacheable_udp_response(std::shared_ptr<UdpQuery> const &query, const dns::Message &received) const;
	void process_upstream_udp_channel(InternalData *d, std::shared_ptr<UdpChannel> const &channel);
	void process_receive(InternalData *d, int upstream_fd);
	std::shared_ptr<Task> find_task_by_fd(int fd) const;
	
	bool reply_to_client_udp(InternalData *d, std::shared_ptr<Task> task, const dns::Message &received);
	bool reply_to_client_udp(InternalData *d, std::shared_ptr<UdpQuery> const &query, const dns::Message &received);
	bool reply_from_cache(InternalData *d, const ProtocolFamilyType &client_proto, const dns::Header &header, const dns::Question &q, uint16_t client_udp_payload);
	std::shared_ptr<Task> make_task(Operation op, uint32_t local_transaction_id);
	void init_epoll_event(Task *task, int fd, uint32_t events);
	void uptime();
	void drop_aa_flag(dns::Message *msg);
	Hosts load_hosts_file(const std::string &suffix, const std::string &path);
	void update_hosts_files(bool force);
	bool is_client_allowed(sa_family_t family, const void *address) const;
	bool consume_rate_limit(sa_family_t family, const void *address);
	
public:
	static bool validate_options(Options const &opts, std::string *error = nullptr);
	static bool validate_runtime_inputs(Options *opts, std::string const &working_directory, std::string *error = nullptr);
	Behind(Options const &opts);
	~Behind();
	bool main(std::function<bool(bool)> const &reload_requested = { });
	// Returns false if any check failed. Only reached via --self-test.
	bool self_test();
};

#endif // BEHIND_H
