#include "ConfigParser.h"
#include "Logger.h"
#include <fcntl.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "rwfile.h"
#include "misc.h"

bool ConfigParser::parse(char const *file, fn_assign_t fn_assign, void *cookie)
{
	std::vector<char> data;
	if (readfile(file, &data) && !data.empty()) {
		std::string section;
		int line = 1;
		char const *begin = data.data();
		char const *end = begin + data.size();
		char const *ptr = begin;
		char const *comment;
		char const *sec;
		char const *key;
		char const *sep;
		char quote;
		auto Reset = [&](){
			comment = nullptr;
			sec = nullptr;
			key = nullptr;
			sep = nullptr;
			quote = 0;
		};
		Reset();
		while (1) {
			int c = 0;
			char const *pre = ptr;
			if (ptr < end) {
				c = (unsigned char)*ptr;
				ptr++;
			}
			if (c == '\n' || c == '\r' || c == 0) {
				if (key) {
					if (sep) {
						if (*sep == '=') {
							std::string k = misc::trimmed(key, sep);
							std::string v = misc::trimmed(sep + 1, comment ? comment : pre);
							if (v.size() >= 2 && v[0] == '\"' && v[v.size() - 1] == '\"') {
								v = v.substr(1, v.size() - 2);
							}
							fn_assign(section, k, v, cookie);
						}
					} else {
						logprintf(LOG_DEFAULT, "unexpected keyword: %s (%d)\n", file, line);
					}
				}
				if (c == 0) break;
				if (c == '\r' && ptr < end && *ptr == '\n') {
					ptr++;
				}
				Reset();
				line++;
			} else if (comment) {
				continue;
			} else if (quote) {
				if (c == quote) {
					quote = 0;
				}
			} else if (c == '\"') {
				quote = c;
			} else if (c == '#' || c == ';' || (c == '/' && ptr < end && *ptr == '/')) {
				comment = pre;
			} else if (c == '[') {
				if (sec) {
					logprintf(LOG_DEFAULT, "unexpected character: %s (%d) '%c'\n", file, line, c);
				} else if (!key) {
					sec = ptr;
				}
			} else if (c == ']') {
				if (sec) {
					section.assign(sec, comment ? comment : pre);
					sec = nullptr;
				} else {
					logprintf(LOG_DEFAULT, "unexpected character: %s (%d) '%c'\n", file, line, c);
				}
			} else if (c == '=') {
				if (key) {
					sep = pre;
				}
			} else if (!isspace(c) && !key && !sec) {
				key = pre;
			}
		}
		return true;
	}
	return false;
}

void ConfigParser::example()
{
	struct Option {
	};

	Option opt;
	char const *file = "example.ini";
	parse(file, [](std::string const &section, std::string const &key, std::string const &value, void *cookie){
		Option *opt = static_cast<Option *>(cookie);

	}, &opt);
}
