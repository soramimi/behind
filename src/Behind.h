#ifndef BEHIND_H
#define BEHIND_H

#include "inetresolver.h"
#include <list>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>
#include "RandomNumber.h"
#include <sys/socket.h>

struct Global {
};

extern Global *global;

namespace misc {
static inline std::string unquote(std::string value)
{
	if (value.size() > 2) {
		if (value[0] == '\"' && value[value.size() - 1] == '\"') {
			value = value.substr(1, value.size() - 2);
		}
	}
	return value;
}
static inline bool to_bool(std::string const &value)
{
	std::string v = unquote(value);
	if (v == "yes") return true;
	if (v == "no") return false;
	return false;
}
}

struct Option {
	bool case_randomize = false;
	void set(std::string const &section, std::string const &key, std::string const &value)
	{
		if (key == "case-randomize") {
			case_randomize = misc::to_bool(value);
			return;


		}
	}
};

enum class DNS_TYPE : uint16_t {
	A = 1,
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
	void add_nxdomain(const std::string &domain);
private:
	static inline bool eqi(std::string const &l, std::string const &r);
	uint16_t listen_port() const;
	void init_ttl();
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
	void write_dns_answer_rr(std::vector<char> *out, std::string const &name, uint16_t clas, uint32_t ttl, dns_record_t const &item);
	int parse_question_section(char const *begin, char const *end, char const *ptr, question_t *out);
	Forwarder get_forwarder();
	void init_forwarder();
	void purge();
	bool take_query(uint16_t id, query_t *out);
	void delete_pending_query(uint16_t id);
	void push_query(query_t const &query);
	void parse_dns_packet(char const *begin, char const *end, dns_header_t *header, std::list<question_t> *questions, std::list<answer_t> *answers);
};

#endif // BEHIND_H
