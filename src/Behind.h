#ifndef BEHIND_H
#define BEHIND_H

#include "DomainFilter.h"
#include "Global.h"
#include "RandomNumber.h"
#include "inetresolver.h"
#include <map>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unordered_map>

#define STANDARD_DNS_PORT 53
#define DEFAUT_LISTEN_PORT 5300

class Hosts {
private:
	std::unordered_map<std::string, InetResolver::Addr> map_;
public:
	InetResolver::Addr const *find(std::string const &name);
	InetResolver::Addr &operator [] (std::string const &name);
};

struct Option {
	int listen_port = DEFAUT_LISTEN_PORT;
	std::string working_dir = "/var/lib/behind";
	std::string log_file = "/var/log/behind/behind.log";
	std::vector<std::string> forward_addr;
	bool case_randomize = false;
	DomainFilter domain_filter;
	std::map<std::string, std::string> hosts;
};

enum class DNS_TYPE : uint16_t {
	A = 1,
	NS = 2,
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	MX = 15,
	AAAA = 28,
};
char const *dns_type_to_string(DNS_TYPE type);

struct Forwarder {
	sa_family_t af_type = AF_UNSPEC;
	uint8_t addr[16] = {0};
	int port = STANDARD_DNS_PORT;
	operator bool () const
	{
		return af_type != AF_UNSPEC;
	}
};

namespace dns {
struct Header;
struct Query;
struct Question;
struct Record;
struct Cache;
struct Message;
}

class Behind {
public:
private:

	struct Private;
	Private *m;

	enum class SocketMode {
		SELECT,
		EPOLL,
	};

	struct Pointers {
		char *begin;
		char *end;
		char *ptr;
	};

private:
	static inline bool eqi(std::string const &l, std::string const &r);
	uint16_t listen_port() const;
	int ttl() const;
	static void write(std::vector<char> *out, char c);
	static void write(std::vector<char> *out, char const *src, int len);
	static void write_us(std::vector<char> *out, uint16_t v);
	static void write_ul(std::vector<char> *out, uint32_t v);
	static void write_us(void *out, uint16_t v);
	static void write_ul(void *out, uint32_t v);
	static bool write_name(std::vector<char> *out, std::map<std::string, size_t> *namemap, std::string const &name);
	static int decode_name(char const *begin, char const *end, char const *ptr, std::vector<char> *out);
	static int decode_name(char const *begin, char const *end, char const *ptr, std::string *name);
	static void write_dns_header(std::vector<char> *out, uint16_t id, uint16_t flags, uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount);
	static void write_dns_question_rr(std::vector<char> *out, std::map<std::string, size_t> *namemap, std::string const &name, DNS_TYPE type, uint16_t clas);
	static bool write_dns_answer_rr(std::vector<char> *out, std::map<std::string, size_t> *namemap, std::string const &name, uint16_t clas, uint32_t ttl, dns::Record const &item);
	static int parse_question_section(char const *begin, char const *end, char const *ptr, dns::Question *out);
	std::vector<Forwarder> get_forwarder();
	void init_forwarder();
	void clean();
	void clean_transaction(uint32_t id);
	bool take_query(uint16_t id, dns::Query *out);
	void push_query(dns::Query const &query);
	static void parse_dns_message(char const *begin, char const *end, dns::Message *msg);

	bool is_nxdomain(std::string const &name) const;
	bool is_nodata_aaaa(std::string const &name) const;

	struct Packet;
	static Packet make_dns_message(dns::Message const &msg);
	bool send_dns_message(void *private_d, int family, dns::Message const &msg, bool forward, bool from_cache);

	void process(void *private_d, int family);

	void init_socket4(void *private_in);
	void init_socket6(void *private_in);
	const InetResolver::Addr *find_host(std::string const &name) const;
	void add_hosts(const std::map<std::string, std::string> &hosts);
	uint32_t next_local_transaction_id();
	int epoll_ctl_add(epoll_event *e);
	int epoll_ctl_del(epoll_event *e);
	bool accept_dns_type(DNS_TYPE t);
public:
	Behind(Option const &opt);
	~Behind();
	void main();
	void test();
};

#endif // BEHIND_H
