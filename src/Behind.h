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

#define DEFAUT_DNS_PORT 53
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
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	AAAA = 28,
};
char const *dns_type_to_string(DNS_TYPE type);

struct Forwarder {
	sa_family_t af_type = AF_UNSPEC;
	uint8_t addr[16] = {0};
	int port = DEFAUT_DNS_PORT;
	operator bool () const
	{
		return af_type != AF_UNSPEC;
	}
};

class Behind {
public:
	struct dns_header_t;
	struct query_t;
	struct question_t;
	struct dns_record_t;
	struct dns_cache_t;
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
	static bool write_dns_answer_rr(std::vector<char> *out, std::map<std::string, size_t> *namemap, const std::string &name, uint16_t clas, uint32_t ttl, dns_record_t const &item);
	static int parse_question_section(char const *begin, char const *end, char const *ptr, question_t *out);
	std::vector<Forwarder> get_forwarder();
	void init_forwarder();
	void clean();
	void clean_transaction(uint32_t id);
	bool take_query(uint16_t id, query_t *out);
	void push_query(query_t const &query);
	static void parse_dns_packet(char const *begin, char const *end, dns_header_t *header, std::vector<question_t> *questions, std::vector<dns_record_t> *answers, std::vector<Behind::dns_record_t> *authority);

	bool is_nxdomain(const std::string &name) const;
	bool is_nodata_aaaa(const std::string &name) const;

	static std::vector<dns_record_t> make_records(const query_t &q, const std::vector<dns_record_t> &answers);
	struct PacketData;
	static PacketData make_packet(void *private_d, const dns_header_t &header, const std::vector<question_t> &questions, const std::vector<dns_record_t> &answer, std::vector<dns_record_t> const &authority);
	bool send_packet(void *private_d, int family, const dns_header_t &header, std::vector<question_t> const &q, std::vector<dns_record_t> const &rec, const std::vector<dns_record_t> &authority, bool forward, bool from_cache);

	void process(void *private_d, int family);

	void init_socket4(void *private_in);
	void init_socket6(void *private_in);
	const InetResolver::Addr *find_host(const std::string &name) const;
	void add_hosts(const std::map<std::string, std::string> &hosts);
	uint32_t next_local_transaction_id();
	int epoll_ctl_add(epoll_event *e);
	int epoll_ctl_del(epoll_event *e);
public:
	Behind(Option const &opt);
	~Behind();
	void main();
	void test();
};

#endif // BEHIND_H
