#include "ConfigParser.h"
#include "Logger.h"
#include <fcntl.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "rwfile.h"
#include "misc.h"
#include <cstdlib>
#include <climits>
#include <cstring>
#include <libgen.h>

bool ConfigParser::parse(char const *file, fn_assign_t fn_assign, void *cookie)
{
	char path[PATH_MAX];
	if (!realpath(file, path)) {
		logprintf(LOG_DEFAULT, "cannot resolve path: %s\n", file);
	}
	file = path;

	std::vector<char> data;
	if (readfile(file, &data) && !data.empty()) {
		logprintf(LOG_DEFAULT, "loading configuration file: %s\n", file);

		std::string section;
		int line = 1;
		char const *begin = data.data();
		char const *end = begin + data.size();
		char const *ptr = begin;
		char const *left;
		char const *comment;
		char const *sec;
		char const *key;
		char const *sep;
		char quote;
		auto Reset = [&](){
			left = ptr;
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
				if (c == '\r' && ptr < end && *ptr == '\n') {
					ptr++;
				}
				if (key) {
					if (strncmp(key, "include", 7) == 0) {
						if (key + 7 < end && isspace((unsigned char)key[7])) {
							std::string path = misc::trimmed(key + 7, pre);
							char const *p = strrchr(file, '/');
							if (p) {
								path = std::string(file, p - file + 1) + path;
							}
							std::vector<char> data2;
							if (readfile(path.c_str(), &data2)) {
								logprintf(LOG_DEFAULT, "including configuration file: %s\n", path.c_str());
								if (!data.empty()) {
									size_t pos = left - begin;
									data.erase(data.begin() + pos, data.begin() + (ptr - begin));
									data.insert(data.begin() + pos, data2.begin(), data2.end());
									begin = data.data();
									end = begin + data.size();
									ptr = begin + pos;
								}
							}
						}
					} else if (sep) {
						if (*sep == '=') {
							std::string k = misc::trimmed(key, sep);
							std::string v = misc::trimmed(sep + 1, comment ? comment : pre);
							if (v.size() >= 2 && v[0] == '\"' && v[v.size() - 1] == '\"') {
								v = v.substr(1, v.size() - 2);
							}
							fn_assign(section, k, v, cookie);
						}
					} else {
						fprintf(stderr, "unexpected keyword: %s (%d)\n", file, line);
					}
				}
				if (c == 0) break;
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
					fprintf(stderr, "unexpected character: %s (%d) '%c'\n", file, line, c);
				} else if (!key) {
					sec = ptr;
				}
			} else if (c == ']') {
				if (sec) {
					section.assign(sec, comment ? comment : pre);
					sec = nullptr;
				} else {
					fprintf(stderr, "unexpected character: %s (%d) '%c'\n", file, line, c);
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
	} else {
		fprintf(stderr, "cannot open configuration file: %s\n", file);
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
