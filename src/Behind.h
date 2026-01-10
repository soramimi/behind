#ifndef BEHIND_H
#define BEHIND_H

#include "inetresolver.h"
#include <list>
#include <map>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "RandomNumber.h"
#include <sys/socket.h>

struct Global {
};

extern Global *global;

struct Option {
	std::string forward_addr;
	bool case_randomize = false;
	std::vector<std::string> nxdomain;
	std::unordered_map<std::string, InetResolver::Addr> hosts;
};

enum class DNS_TYPE : uint16_t {
	A = 1,
	CNAME = 5,
	PTR = 12,
	AAAA = 28,
};

struct Forwarder {
	sa_family_t af_type = AF_UNSPEC;
	uint8_t addr[16] = {0};
	int port = 53;
	operator bool () const
	{
		return af_type != AF_UNSPEC;
	}
};

class Behind {
	friend class Cache;
public:
private:
	struct dns_record_t;
	struct dns_header_t;
	struct query_t;
	struct question_t;
	struct answer_t;
	struct dns_cache_t;

	struct Private;
	Private *m;

public:
	Behind(Option const &opt);
	~Behind();
	void main();
private:
	static inline bool eqi(std::string const &l, std::string const &r);
	uint16_t listen_port() const;
	int ttl() const;
	static void write(std::vector<char> *out, char c);
	static void write(std::vector<char> *out, char const *src, int len);
	static void write_us(std::vector<char> *out, uint16_t v);
	static void write_ul(std::vector<char> *out, uint32_t v);
	void write_name(std::vector<char> *out, std::string const &name);
	int decode_name(char const *begin, char const *end, char const *ptr, std::vector<char> *out);
	int decode_name(char const *begin, char const *end, char const *ptr, std::string *name);
	static void write_dns_header(std::vector<char> *out, uint16_t id, uint16_t flags, uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount);
	void write_dns_question_rr(std::vector<char> *out, std::string const &name, DNS_TYPE type, uint16_t clas);
	void write_dns_answer_rr(std::vector<char> *out, const std::string &name, uint16_t clas, uint32_t ttl, dns_record_t const &item);
	int parse_question_section(char const *begin, char const *end, char const *ptr, question_t *out);
	Forwarder get_forwarder();
	void init_forwarder();
	void clean();
	bool take_query(uint16_t id, query_t *out);
	void delete_pending_query(uint16_t id);
	void push_query(query_t const &query);
	void parse_dns_packet(char const *begin, char const *end, dns_header_t *header, std::list<question_t> *questions, std::list<answer_t> *answers);

	bool is_nxdomain(const std::string &name);
	void send_response(void *private_d, int family, const dns_header_t &header, const question_t &q, std::vector<dns_record_t> const &rec);
	void process(void *private_d, int family);
};

#endif // BEHIND_H
