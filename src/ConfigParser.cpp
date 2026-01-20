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
#include "LineReader.h"

bool ConfigParser::parse(char const *file, fn_assign_t fn_assign, void *cookie)
{
	LineReader reader;
	if (reader.open(file)) {
		std::string line;
		std::string section;
		while (reader.getline(&line)) {
			char const *begin = line.c_str();
			char const *end = begin + line.size();
			char const *ptr = begin;
			char const *comment = nullptr;
			char const *sec = nullptr;
			char const *key = nullptr;
			char const *sep = nullptr;
			char quote = 0;
			while (1) {
				int c = 0;
				char const *pre = ptr;
				if (ptr < end) {
					c = (unsigned char)*ptr;
					ptr++;
				}
				if (c == 0) {
					if (key) {
						std::string k = misc::trimmed(key, sep);
						std::string v = misc::trimmed(sep + 1, comment ? comment : pre);
						if (v.size() >= 2 && v[0] == '\"' && v[v.size() - 1] == '\"') {
							v = v.substr(1, v.size() - 2);
						}
						fn_assign(section, k, v, cookie);
						break;
					}
					if (c == 0) break;
				} else if (quote) {
					if (c == quote) {
						quote = 0;
					}
				} else if (c == '\"' || c == '\'') {
					quote = c;
				} else if (c == ';') {
					comment = pre;
					break;
				} else if (c == '[') {
					if (sec) {
						fprintf(stderr, "unexpected character: %s (%d) '%c'\n", file, line, c);
					} else if (!key) {
						sec = ptr;
					}
				} else if (c == ']') {
					if (sec) {
						section.assign(sec, pre);
						sec = nullptr;
						key = nullptr;
					} else {
						fprintf(stderr, "unexpected character: %s (%d) '%c'\n", file, line, c);
					}
				} else if (c == '=') {
					if (key) {
						sep = pre;
					}
				} else if (!isspace(c) && !key) {
					key = pre;
				}
			}
		}
	}
	return true;
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
