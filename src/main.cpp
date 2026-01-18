
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

	if (section == "forward-zone") {
		if (key == "forward-addr") {
			opt->forward_addr = value;
			return true;
		}
	} else if (section == "security") {
		if (key == "case-randomize") {
			opt->case_randomize = IsTrue(value);
			return true;
		}
	} else if (section == "nxdomain") {
		if (key == "addr") {
			opt->nxdomain.insert(opt->nxdomain.end(), value);
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
						logprintf(LOG_DEFAULT, "failed to open config file: %s\n", confpath.c_str());
						ok = false;
					}
				} else {
					logprintf(LOG_DEFAULT, "Option %s requires an argument.\n", arg);
					ok = false;
				}
			} else {
				logprintf(LOG_DEFAULT, "Unknown option: %s\n", arg);
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
	if (::getcwd(buf, sizeof(buf)) != nullptr) {
		return std::string(buf);
	} else {
		return std::string();
	}
}

int main(int argc, char **argv)
{
	Global g;
	global = &g;

	misc::get_tick_count(); // dummy read for initialize

	Logger::start();

	logprintf(LOG_DEFAULT, "=== Starting BEHIND DNS Server ===\n");

	std::string cwd = getcwd();
	logprintf(LOG_DEFAULT, "current working directory: %s\n", cwd.c_str());

	for (int i = 1; i < argc; i++) {
		logprintf(LOG_DEFAULT, "argv[%d] = %s\n", i, argv[i]);
	}

	Option opt;
	parse_option(argc, argv, &opt);
	Behind ns(opt);
	ns.test();
	main2(&ns);

	Logger::stop();

	return 0;
}

