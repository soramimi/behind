
#include "Behind.h"
#include "Logger.h"
#include "ConfigParser.h"
#include "misc.h"
#include "network.h"
#include "rwfile.h"
#include <optional>
#include <string.h>
#include <unistd.h>

bool set_option(std::string const &section, std::string const &key, std::string const &value, Option *opt)
{
	auto IsTrue = [](std::string const &val){
		if (val == "yes") return true;
		if (val == "true") return true;
		if (val == "no") return false;
		if (val == "false") return false;
		logprintf(LOG_DEFAULT, "invalid boolean value: %s\n", val.c_str());
		return false;
	};

	std::vector<std::string_view> section_parts = misc::split(section);
	std::string const &sec = section_parts.empty() ? section : std::string(section_parts.front());

	if (sec == "options") {
		if (key == "directory") {
			opt->working_dir = value;
			return true;
		}
		if (key == "listen") {
			auto addrport = InetAddrPort::parse(value);
			if (addrport.port == 0) {
				addrport.port = DEFAUT_LISTEN_PORT;
			}
			if (addrport.addr.type == InetResolver::IN4) {
				opt->listen4 = addrport;
				return true;
			} else if (addrport.addr.type == InetResolver::IN6) {
				opt->listen6 = addrport;
				return true;
			} else {
				logprintf(LOG_DEFAULT, "invalid listen address: %s\n", value.c_str());
				return false;
			}
		}
	} else if (sec == "logging") {
		if (key == "file") {
			opt->log_file = value;
			return true;
		}
	} else if (sec == "forward-zone") {
		if (key == "forward-addr") {
			std::string zone;
			if (section_parts.size() >= 2) {
				zone = section_parts[1];
				zone = misc::unquote(zone);
				zone = misc::strtolower(zone);
			}
			if (zone.empty()) {
				zone = ".";
			} else if (zone.back() != '.') {
				zone += '.';
			}
			Option::Zone z;
			z.zone = zone;
			z.name = value;
			opt->forward_addr.push_back(z);
			return true;
		}
	} else if (sec == "security") {
		if (key == "case-randomize") {
			opt->case_randomize = IsTrue(value);
			return true;
		}
	} else if (sec == "filter") {
		if (key == "nxdomain") {
			opt->domain_filter.add_nxdomain(value);
			return true;
		}
		if (key == "nodata-aaaa") {
			opt->domain_filter.add_nodata_aaaa(value);
			return true;
		}
	} else if (sec == "hosts") {
		std::string suffix;
		if (section_parts.size() >= 2) {
			suffix = misc::unquote(section_parts[1]);
		}
		if (key[0] == '"') {
			std::string name = misc::unquote(key);
			if (!name.empty()) {
				Option::Host h;
				h.name = name;
				h.suffix = suffix;
				h.address = value;
				opt->hosts.push_back(h);
			}
		} else if (key == "file") {
			logprintf(LOG_STDERR, "--- file = %s\n", value.c_str());
			Option::HostsFile hf;
			hf.suffix = suffix;
			hf.path = value;
			opt->hostsfiles.push_back(hf);
		}
		return true;
	} else {
		logprintf(LOG_DEFAULT, "unknown section: [%s]\n", sec.c_str());
		return false;
	}
	logprintf(LOG_DEFAULT, "unknown option: [%s] %s\n", sec.c_str(), key.c_str());
	return false;
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
					ok = ConfigParser::parse(confpath.c_str(), [](std::string const &section, std::string const &key, std::string const &value, void *cookie){
						Option *opt = static_cast<Option *>(cookie);
						set_option(section, key, value, opt);
					}, opt);
					if (!ok) {
						fprintf(stderr, "failed to open config file: %s\n", confpath.c_str());
						ok = false;
					}
				} else {
					fprintf(stderr, "option %s requires an argument.\n", arg);
					ok = false;
				}
			} else if (strcmp(arg, "--log-file") == 0) {
				if (argi < argc) {
					opt->log_file = argv[argi++];
				} else {
					fprintf(stderr, "option %s requires an argument.\n", arg);
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

std::string getcwd()
{
	char buf[4096];
	if (::getcwd(buf, sizeof(buf))) {
		return std::string(buf);
	}
	return {};
}

#include "DomainFilter.h"
#include <assert.h>
#define EXPECT_EQ(a, b) assert((a) == (b))

extern bool sighup_caught;

void main2(int argc, char **argv)
{

	Option opt;
	parse_option(argc, argv, &opt);

	Logger::open(opt.log_file);
	Logger::pause(false);
	logprintf(LOG_BOTH, "log file: %s\n", misc::realpath(opt.log_file.c_str()).c_str());

	if (!opt.working_dir.empty()) {
		chdir(opt.working_dir.c_str());
	}
	std::string cwd = getcwd();
	logprintf(LOG_BOTH, "current working directory: %s\n", cwd.c_str());

	Behind behind(opt);

	behind.test();
	behind.main();
}

int main(int argc, char **argv)
{
	Global g;
	global = &g;

	misc::get_tick_count(); // dummy read for initialize

	Logger::start();
	Logger::pause(true);
	logprintf(LOG_DEFAULT, "=== Starting BEHIND DNS Server ===\n");
	for (int i = 1; i < argc; i++) {
		logprintf(LOG_DEFAULT, "argv[%d] = %s\n", i, argv[i]);
	}

	while (1) {
		main2(argc, argv);

		if (sighup_caught) {
			sighup_caught = false;
			continue;
		} else {
			break;
		}
	}

	Logger::stop();

	return 0;
}

