
#include "Behind.h"
#include "ConfigParser.h"
#include "Logger.h"
#include "misc.h"
#include "network.h"
#include "rwfile.h"
#include <cerrno>
#include <optional>
#include <string.h>
#include <unistd.h>

bool set_option(std::string const &section, std::string const &key, std::string const &value, Option *opt)
{
	std::vector<std::string_view> section_parts = misc::split(section);
	std::string const &sec = section_parts.empty() ? section : std::string(section_parts.front());

	if (sec == "options") {
		if (key == "directory") {
			opt->working_dir = value;
			return true;
		}
		if (key == "max-tasks") {
			int v = 0;
			if (misc::parse_int(value.c_str(), &v) > 0 && v > 0) {
				opt->max_tasks = (size_t)v;
				return true;
			}
			logprintf(LOG_DEFAULT, "invalid max-tasks: %s\n", value.c_str());
			return false;
		}
		if (key == "max-cache-entry-size") {
			int v = 0;
			if (misc::parse_int(value.c_str(), &v) > 0 && v > 0) {
				opt->max_cache_entry_size = (size_t)v;
				return true;
			}
			logprintf(LOG_DEFAULT, "invalid max-cache-entry-size: %s\n", value.c_str());
			return false;
		}
		if (key == "max-ttl") {
			int v = 0;
			if (misc::parse_int(value.c_str(), &v) > 0 && v > 0) {
				opt->max_ttl = (uint32_t)v;
				return true;
			}
			logprintf(LOG_DEFAULT, "invalid max-ttl: %s\n", value.c_str());
			return false;
		}
		if (key == "edns0-buffer-size") {
			int v = 0;
			if (misc::parse_int(value.c_str(), &v) > 0 && v >= 512 && v <= 65535) {
				opt->edns0_buffer_size = (uint16_t)v;
				return true;
			}
			logprintf(LOG_DEFAULT, "invalid edns0-buffer-size: %s\n", value.c_str());
			return false;
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
	} else if (sec == "filter") {
		if (key == "nxdomain") {
			opt->domain_filter.add_nxdomain(value);
			return true;
		}
		if (key == "nodata") {
			opt->domain_filter.add_nodata(value);
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
	*opt = { };
	int argi = 1;
	while (argi < argc) {
		char const *arg = argv[argi++];
		if (arg[0] == '-') {
			if (strcmp(arg, "-C") == 0 || strcmp(arg, "--conf") == 0) {
				if (argi < argc) {
					std::string confpath;
					{
						std::string path = argv[argi++];
						confpath = misc::realpath(path);
						if (confpath.empty()) {
							fprintf(stderr, "invalid config path: %s\n", path.c_str());
							ok = false;
						}
					}
					ok = ConfigParser::parse(confpath.c_str(), [](std::string const &section, std::string const &key, std::string const &value, void *cookie) {
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
	return { };
}

#include "DomainFilter.h"
#include <assert.h>
#define EXPECT_EQ(a, b) assert((a) == (b))

#include <atomic>
extern std::atomic<bool> sighup_caught;
extern std::atomic<bool> sigint_caught;

bool main2(int argc, char **argv)
{

	Option opt;
	if (!parse_option(argc, argv, &opt)) {
		return false;
	}

	Logger::open(opt.log_file);
	Logger::pause(false);
	logprintf(LOG_BOTH, "log file: %s\n", misc::realpath(opt.log_file.c_str()).c_str());

	if (!opt.working_dir.empty()) {
		if (chdir(opt.working_dir.c_str()) != 0) {
			logprintf(LOG_BOTH, "failed to chdir to %s: %s\n", opt.working_dir.c_str(), strerror(errno));
			return false;
		}
	}
	std::string cwd = getcwd();
	logprintf(LOG_BOTH, "current working directory: %s\n", cwd.c_str());

	Behind behind(opt);

	behind.test();
	behind.main();
	return true;
}

int main(int argc, char **argv)
{
	misc::get_tick_count(); // dummy read for initialize

	Logger::start();
	Logger::pause(true);
	logprintf(LOG_DEFAULT, "=== Starting BEHIND DNS Server ===\n");
	for (int i = 1; i < argc; i++) {
		logprintf(LOG_DEFAULT, "argv[%d] = %s\n", i, argv[i]);
	}

	while (1) {
		bool ok = main2(argc, argv);
		if (!ok) {
			break;
		}

		if (sighup_caught.load(std::memory_order_relaxed)) {
			sighup_caught.store(false, std::memory_order_relaxed);
			logprintf(LOG_DEFAULT, "=== SIGHUP ===\n");
			continue;
		}
		if (sigint_caught.load(std::memory_order_relaxed)) {
			logprintf(LOG_DEFAULT, "=== SIGINT ===\n");
		}
		break;
	}

	Logger::stop();

	return 0;
}
