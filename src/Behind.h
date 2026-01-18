#ifndef BEHIND_H
#define BEHIND_H

#include "RandomNumber.h"
#include "inetresolver.h"
#include <map>
#include <sys/socket.h>
#include <unordered_map>

struct Global {
};

extern Global *global;

class Hosts {
private:
	std::unordered_map<std::string, InetResolver::Addr> map_;
public:
	InetResolver::Addr const *find(std::string const &name);
	InetResolver::Addr &operator [] (std::string const &name);
};

struct Option {
	std::string forward_addr;
	bool case_randomize = false;
	std::vector<std::string> nxdomain;
	Hosts hosts;

};

enum class DNS_TYPE : uint16_t {
	A = 1,
	CNAME = 5,
	PTR = 12,
	AAAA = 28,
};
char const *dns_type_to_string(DNS_TYPE type);

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
	struct dns_header_t;
	struct query_t;
	struct question_t;
	struct dns_record_t;
	struct dns_cache_t;
private:

	struct Private;
	Private *m;

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
	Forwarder get_forwarder();
	void init_forwarder();
	void clean();
	bool take_query(uint16_t id, query_t *out);
	void delete_pending_query(uint16_t id);
	void push_query(query_t const &query);
	static void parse_dns_packet(char const *begin, char const *end, dns_header_t *header, std::vector<question_t> *questions, std::vector<dns_record_t> *answers);

	bool is_nxdomain(const std::string &name);

	static std::vector<dns_record_t> make_records(const query_t &q, const std::vector<dns_record_t> &answers);
	struct ResponseData;
	static ResponseData make_response(void *private_d, const dns_header_t &header, const std::vector<question_t> &questions, const std::vector<dns_record_t> &rec);
	bool send_response(void *private_d, int family, const dns_header_t &header, std::vector<question_t> const &q, std::vector<dns_record_t> const &rec);

	void process(void *private_d, int family);

public:
	Behind(Option const &opt);
	~Behind();
	void main();
	void test();
};

#endif // BEHIND_H
