
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#endif

#include "Behind.h"
#include "network.h"
#include "misc.h"
#include <string.h>
#include "rwfile.h"
#include <optional>

Global *global;

std::vector<std::string_view> split_lines(char const *begin, char const *end)
{
	std::vector<std::string_view> lines;
	char const *ptr = begin;
	char const *left = begin;
	while (1) {
		int c = 0;
		if (ptr < end) {
			c = (unsigned char)*ptr;
		}
		if (c == '\n' || c == '\r' || c == 0) {
			std::string_view line(left, ptr - left);
			lines.push_back(line);
			if (c == 0) {
				break;
			}
			ptr++;
			if (c == '\r') {
				if (ptr + 1 < end && ptr[1] == '\n') {
					ptr++;
				}
			}
			left = ptr;
		} else {
			ptr++;
		}
	}
	return lines;
}

std::string trimmed(std::string_view const &s)
{
	char const *left = s.data();
	char const *right = s.data() + s.size();
	while (left < right && isspace((unsigned char)*left)) left++;
	while (left < right && isspace((unsigned char)right[-1])) right--;
	return std::string(left, right - left);
}

void parse_conf_file(std::vector<std::string_view> const &lines, Option *opt)
{
	std::string section;
	size_t index = 0;
	while (index < lines.size()) {
		std::string line = std::string(lines[index]);
		index++;
		while (!line.empty() && line.back() == '\\' && index < lines.size()) {
			line.append(lines[index]);
			index++;
		}
		line = trimmed(line);
		if (line.empty()) continue;
		char const *begin = line.data();
		char const *end = begin + line.size();
		if (line[0] == '[') {
			char const *ptr = begin + 1;
			char const *left = ptr;
			char quote = 0;
			while (1) {
				int c = 0;
				if (ptr < end) {
					c = (unsigned char)*ptr;
				}
				if (quote) {
					if (c == quote) {
						quote = 0;
					}
				} else if (c == 0 || c == '#') {
					break;
				} else if (c == '\"') {
					quote = c;
				} else if (c == ']') {
					section.assign(left, ptr - left);
					break;
				}
				ptr++;
			}
		} else {
			char const *ptr = begin;
			char const *key = begin;
			char const *eq = nullptr;
			char quote = 0;
			while (1) {
				int c = 0;
				if (ptr < end) {
					c = (unsigned char)*ptr;
				}
				if (quote) {
					if (c == quote) {
						quote = 0;
					}
				} else if (c == 0 || c == '#') {
					if (eq) {
						std::string k = trimmed({key, eq - key});
						std::string v = trimmed({eq + 1, ptr - eq - 1});
						opt->set(section, k, v);
					}
					break;
				} else if (c == '\"') {
					quote = c;
				} else if (c == '=') {
					eq = ptr;
				}
				ptr++;
			}
		}
	}
}

std::optional<std::vector<std::string_view>> read_conf_file(std::string const &path, std::vector<char> *data)
{
	if (readfile(path.c_str(), data, 1024 * 1024)) {
		if (!data->empty()) {
			return split_lines(data->data(), data->data() + data->size());
		}
		fprintf(stderr, "Config file is empty: %s\n", path.c_str());
	} else {
		fprintf(stderr, "Failed to read config file: %s\n", path.c_str());
	}
	return std::nullopt;
}

bool parse_option(int argc, char **argv, Option *opt)
{
	bool ok = true;
	*opt = {};
	int argi = 1;
	while (argi < argc) {
		char const *arg = argv[argi++];
		if (arg[0] == '-') {
			if (strcmp(arg, "-C") == 0 || strcmp(arg, "--conf") == 0) {
				if (argi < argc) {
					std::string confpath = argv[argi++];
					std::vector<char> data;
					auto ret = read_conf_file(confpath, &data);
					if (ret) {
						std::vector<std::string_view> const &lines = *ret;
						parse_conf_file(lines, opt);
					} else {
						ok = false;
					}
				} else {
					fprintf(stderr, "Option %s requires an argument.\n", arg);
					ok = false;
				}
			} else {
				fprintf(stderr, "Unknown option: %s\n", arg);
				ok = false;
			}
		}
	}
	return ok;
}

int main2(Behind *ns, Option *opt)
{
	auto Perform = [&](){
		try {
			ns->main();
		} catch (std::string const &e) {
			fprintf(stderr, "%s\n", e.c_str());
		}
	};

	Perform();
	return 0;
}

int main(int argc, char **argv)
{
	misc::get_tick_count(); // dummy read for initialize

	Global g;
	global = &g;

	Option opt;
	parse_option(argc, argv, &opt);
	Behind ns(opt);
	main2(&ns, &opt);

	return 0;
}

