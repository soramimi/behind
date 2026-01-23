
#include "Behind.h"
#include "Logger.h"
#include "ConfigParser.h"
#include "misc.h"
#include "network.h"
#include "rwfile.h"
#include <optional>
#include <string.h>
#include <unistd.h>

InetResolver::Type parse_inet_address(std::string name, InetResolver::Addr *addr_out, int *port_out);

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

	if (section == "options") {
		if (key == "directory") {
			opt->working_dir = value;
			return true;
		}
		if (key == "port") {
			int port = DEFAUT_LISTEN_PORT;
			if (misc::parse_int(value.c_str(), &port) > 0) {
				opt->listen_port = port;
				return true;
			}
			logprintf(LOG_DEFAULT, "invalid port number: %s\n", value.c_str());
			return false;
		}
	} else if (section == "logging") {
		if (key == "file") {
			opt->log_file = value;
			return true;
		}
	} else if (section == "forward-zone") {
		if (key == "forward-addr") {
			opt->forward_addr.push_back(value);
			return true;
		}
	} else if (section == "security") {
		if (key == "case-randomize") {
			opt->case_randomize = IsTrue(value);
			return true;
		}
	} else if (section == "filter") {
		if (key == "nxdomain") {
			opt->domain_filter.add_nxdomain(value);
			return true;
		}
		if (key == "nodata-aaaa") {
			opt->domain_filter.add_nodata_aaaa(value);
			return true;
		}
	} else if (section == "hosts") {
		opt->hosts[key] = value;
		return true;
	} else {
		logprintf(LOG_DEFAULT, "unknown section: [%s]\n", section.c_str());
		return false;
	}
	logprintf(LOG_DEFAULT, "unknown option: [%s] %s\n", section.c_str(), key.c_str());
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

int main2(Behind *ns)
{
	auto Perform = [&](){
		try {
			ns->main();
		} catch (std::string const &e) {
			logprintf(LOG_DEFAULT, "%s\n", e.c_str());
			fprintf(stderr, "%s\n", e.c_str());
		}
	};

	Perform();
	return 0;
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

int main(int argc, char **argv)
{
	{
		DomainFilter filter;
		filter.add_nxdomain("doubleclick.net");
		EXPECT_EQ(filter.find("doubleclick.net"), DomainFilter::NXDOMAIN);
		EXPECT_EQ(filter.find("ads.doubleclick.net"), DomainFilter::NXDOMAIN);
		// return 0;
	}

	Global g;
	global = &g;

	misc::get_tick_count(); // dummy read for initialize

	Logger::start();
	Logger::pause(true);
	logprintf(LOG_DEFAULT, "=== Starting BEHIND DNS Server ===\n");
	for (int i = 1; i < argc; i++) {
		logprintf(LOG_DEFAULT, "argv[%d] = %s\n", i, argv[i]);
	}

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
	main2(&behind);

	Logger::stop();

	return 0;
}

