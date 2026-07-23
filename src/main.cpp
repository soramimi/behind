
#include "Behind.h"
#include "ConfigParser.h"
#include "Logger.h"
#include "misc.h"
#include "network.h"
#include "rwfile.h"
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <future>
#include <limits>
#include <optional>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

bool option_error(std::string *error, std::string message)
{
	if (error) *error = std::move(message);
	return false;
}

bool parse_unsigned(std::string const &text, uint64_t minimum, uint64_t maximum,
	uint64_t *out)
{
	if (text.empty()) return false;
	uint64_t value = 0;
	auto result = std::from_chars(text.data(), text.data() + text.size(), value, 10);
	if (result.ec != std::errc() || result.ptr != text.data() + text.size() || value < minimum || value > maximum) {
		return false;
	}
	*out = value;
	return true;
}

bool validate_section(std::vector<std::string_view> const &parts, std::string *error)
{
	if (parts.empty()) {
		return option_error(error, "an option must appear inside a section");
	}
	std::string const section(parts.front());
	if (section == "options" || section == "logging" || section == "filter") {
		if (parts.size() != 1) {
			return option_error(error, "section [" + section + "] does not accept a qualifier");
		}
		return true;
	}
	if (section == "forward-zone" || section == "hosts") {
		if (parts.size() > 2) {
			return option_error(error, "section [" + section + "] accepts at most one qualifier");
		}
		if (parts.size() == 2 && misc::unquote(parts[1]).empty()) {
			return option_error(error, "section [" + section + "] qualifier must not be empty");
		}
		return true;
	}
	return option_error(error, "unknown section: [" + section + "]");
}

std::string path_from_startup_directory(std::string const &path,
	std::string const &startup_directory)
{
	if (path.empty() || path.front() == '/') return path;
	if (startup_directory.empty() || startup_directory == "/") {
		return startup_directory + path;
	}
	return startup_directory + '/' + path;
}

}

bool set_option(std::string const &section, std::string const &key, std::string const &value,
	Option *opt, std::string *error)
{
	std::vector<std::string_view> section_parts = misc::split(section);
	if (!validate_section(section_parts, error)) return false;
	if (key.empty()) return true; // Section declaration validation.
	std::string const sec(section_parts.front());

	if (sec == "options") {
		if (key == "directory") {
			if (value.empty()) return option_error(error, "directory must not be empty");
			opt->working_dir = value;
			return true;
		}
		if (key == "max-tasks") {
			uint64_t v = 0;
			if (parse_unsigned(value, 1, std::numeric_limits<size_t>::max(), &v)) {
				opt->max_tasks = static_cast<size_t>(v);
				return true;
			}
			return option_error(error, "invalid max-tasks value: " + value);
		}
		if (key == "max-cache-entry-size") {
			uint64_t v = 0;
			if (parse_unsigned(value, 1, std::numeric_limits<size_t>::max(), &v)) {
				opt->max_cache_entry_size = static_cast<size_t>(v);
				return true;
			}
			return option_error(error, "invalid max-cache-entry-size value: " + value);
		}
		if (key == "max-cache-bytes") {
			uint64_t v = 0;
			if (parse_unsigned(value, 1, std::numeric_limits<size_t>::max(), &v)) {
				opt->max_cache_bytes = static_cast<size_t>(v);
				return true;
			}
			return option_error(error, "invalid max-cache-bytes value: " + value);
		}
		if (key == "max-ttl") {
			uint64_t v = 0;
			if (parse_unsigned(value, 1, std::numeric_limits<uint32_t>::max(), &v)) {
				opt->max_ttl = static_cast<uint32_t>(v);
				return true;
			}
			return option_error(error, "invalid max-ttl value: " + value);
		}
		if (key == "edns0-buffer-size") {
			uint64_t v = 0;
			if (parse_unsigned(value, 512, 65535, &v)) {
				opt->edns0_buffer_size = static_cast<uint16_t>(v);
				return true;
			}
			return option_error(error, "invalid edns0-buffer-size value: " + value);
		}
		if (key == "rate-limit-qps") {
			uint64_t v = 0;
			if (parse_unsigned(value, 1, std::numeric_limits<unsigned>::max(), &v)) {
				opt->rate_limit_qps = static_cast<unsigned>(v);
				return true;
			}
			return option_error(error, "invalid rate-limit-qps value: " + value);
		}
		if (key == "rate-limit-burst") {
			uint64_t v = 0;
			if (parse_unsigned(value, 1, std::numeric_limits<unsigned>::max(), &v)) {
				opt->rate_limit_burst = static_cast<unsigned>(v);
				return true;
			}
			return option_error(error, "invalid rate-limit-burst value: " + value);
		}
		if (key == "upstream-timeout-ms") {
			uint64_t v = 0;
			if (parse_unsigned(value, 1, std::numeric_limits<unsigned>::max(), &v)) {
				opt->upstream_timeout_ms = static_cast<unsigned>(v);
				return true;
			}
			return option_error(error, "invalid upstream-timeout-ms value: " + value);
		}
		if (key == "allow-client") {
			if (value.empty()) return option_error(error, "allow-client must not be empty");
			opt->allow_clients.push_back(value);
			return true;
		}
		if (key == "listen") {
			if (value.empty()) return option_error(error, "listen must not be empty");
			auto addrport = InetAddrPort::parse(value);
			if (value.find('@') != std::string::npos && addrport.port == 0) {
				return option_error(error, "invalid listen port: " + value);
			}
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
				return option_error(error, "invalid listen address: " + value);
			}
		}
	} else if (sec == "logging") {
		if (key == "file") {
			if (value.empty()) return option_error(error, "log file must not be empty");
			opt->log_file = value;
			return true;
		}
	} else if (sec == "forward-zone") {
		if (key == "forward-addr") {
			if (value.empty()) return option_error(error, "forward-addr must not be empty");
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
			if (!misc::is_valid_domain(zone)) {
				return option_error(error, "invalid forward zone: " + zone);
			}
			Option::Zone z;
			z.zone = zone;
			z.name = value;
			opt->forward_addr.push_back(z);
			return true;
		}
	} else if (sec == "filter") {
		if (key == "nxdomain") {
			return opt->domain_filter.add_nxdomain(value, error);
		}
		if (key == "nodata") {
			return opt->domain_filter.add_nodata(value, error);
		}
		if (key == "nodata-aaaa") {
			return opt->domain_filter.add_nodata_aaaa(value, error);
		}
	} else if (sec == "hosts") {
		std::string suffix;
		if (section_parts.size() >= 2) {
			suffix = misc::unquote(section_parts[1]);
			if (!suffix.empty() && suffix.back() == '.') suffix.pop_back();
			if (suffix.empty()) {
				return option_error(error, "hosts suffix must not be empty");
			}
		}
		if (!suffix.empty() && !misc::is_valid_domain(suffix)) {
			return option_error(error, "invalid hosts suffix: " + suffix);
		}
		if (key.size() >= 2 && key.front() == '"' && key.back() == '"') {
			std::string name = misc::unquote(key);
			if (name.empty()) return option_error(error, "host name must not be empty");
			std::string full_name = name;
			if (!suffix.empty() && full_name.back() != '.') {
				full_name += '.' + suffix;
			}
			if (!misc::is_valid_domain(full_name)) {
				return option_error(error, "invalid host name: " + full_name);
			}
			auto address = InetAddrPort::parse(value);
			if (!address || value.find('@') != std::string::npos) {
				return option_error(error, "invalid host address: " + value);
			}
			Option::Host h;
			h.name = name;
			h.suffix = suffix;
			h.address = value;
			opt->hosts.push_back(std::move(h));
			return true;
		} else if (key == "file") {
			if (value.empty()) return option_error(error, "hosts file path must not be empty");
			Option::HostsFile hf;
			hf.suffix = suffix;
			hf.path = value;
			opt->hostsfiles.push_back(std::move(hf));
			return true;
		}
	}
	return option_error(error, "unknown option in [" + sec + "]: " + key);
}

bool parse_option(int argc, char **argv, std::string const &startup_directory,
	Option *opt, bool *check_config)
{
	*opt = { };
	*check_config = false;
	std::optional<std::string> log_file_override;
	int argi = 1;
	while (argi < argc) {
		char const *arg = argv[argi++];
		if (arg[0] == '-') {
			if (strcmp(arg, "-C") == 0 || strcmp(arg, "--conf") == 0) {
				if (argi < argc) {
					std::string path = path_from_startup_directory(argv[argi++], startup_directory);
					std::string confpath = misc::realpath(path);
					if (confpath.empty()) {
						fprintf(stderr, "%s: cannot resolve configuration path: %s\n",
							path.c_str(), strerror(errno));
						return false;
					}
					if (!ConfigParser::parse(confpath.c_str(), [](std::string const &section, std::string const &key, std::string const &value, void *cookie, std::string *error) {
							Option *opt = static_cast<Option *>(cookie);
							return set_option(section, key, value, opt, error); }, opt)) {
						return false;
					}
				} else {
					fprintf(stderr, "option %s requires an argument.\n", arg);
					return false;
				}
			} else if (strcmp(arg, "--log-file") == 0) {
				if (argi < argc) {
					std::string value = argv[argi++];
					if (value.empty()) {
						fprintf(stderr, "option %s requires a non-empty argument.\n", arg);
						return false;
					}
					log_file_override = std::move(value);
				} else {
					fprintf(stderr, "option %s requires an argument.\n", arg);
					return false;
				}
			} else if (strcmp(arg, "--check-config") == 0) {
				*check_config = true;
			} else {
				fprintf(stderr, "unknown option: %s\n", arg);
				return false;
			}
		} else {
			fprintf(stderr, "unexpected positional argument: %s\n", arg);
			return false;
		}
	}
	if (log_file_override) opt->log_file = std::move(*log_file_override);
	return true;
}

std::string current_working_directory()
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
extern std::atomic<bool> sigint_caught;

bool validate_configuration(Option *opt, std::string const &startup_directory)
{
	if (!opt) {
		fprintf(stderr, "configuration validation failed: no configuration was provided\n");
		return false;
	}
	std::string error;
	if (!Behind::validate_options(*opt, &error)) {
		if (error.empty()) error = "unspecified validation error";
		fprintf(stderr, "configuration validation failed: %s\n", error.c_str());
		return false;
	}
	std::string working_directory = path_from_startup_directory(opt->working_dir,
		startup_directory);
	struct stat info = { };
	if (stat(working_directory.c_str(), &info) != 0 || !S_ISDIR(info.st_mode) || access(working_directory.c_str(), X_OK) != 0) {
		fprintf(stderr, "configuration validation failed: working directory is not accessible: %s\n",
			working_directory.c_str());
		return false;
	}
	for (Option::HostsFile const &hosts : opt->hostsfiles) {
		std::string path = hosts.path;
		if (!path.empty() && path.front() != '/') {
			path = working_directory + (working_directory.back() == '/' ? "" : "/") + path;
		}
		if (stat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
			fprintf(stderr, "configuration validation failed: hosts file is not accessible: %s\n",
				path.c_str());
			return false;
		}
	}
	if (!Behind::validate_runtime_inputs(opt, working_directory, &error)) {
		fprintf(stderr, "configuration validation failed: %s\n", error.c_str());
		return false;
	}
	return true;
}

bool main2(Option const &opt, std::string const &startup_directory,
	std::function<bool(bool)> const &reload_requested)
{
	std::string log_file = path_from_startup_directory(opt.log_file, startup_directory);
	Logger::open(log_file);
	Logger::pause(false);
	logprintf(LOG_BOTH, "log file: %s\n", log_file.c_str());

	if (!opt.working_dir.empty()) {
		std::string working_dir = path_from_startup_directory(opt.working_dir, startup_directory);
		if (chdir(working_dir.c_str()) != 0) {
			logprintf(LOG_BOTH, "failed to chdir to %s: %s\n", working_dir.c_str(), strerror(errno));
			return false;
		}
	}
	std::string cwd = current_working_directory();
	logprintf(LOG_BOTH, "current working directory: %s\n", cwd.c_str());

	Behind behind(opt);

	behind.self_test();
	return behind.main(reload_requested);
}

int main(int argc, char **argv)
{
	misc::get_tick_count(); // dummy read for initialize
	std::string const startup_directory = current_working_directory();
	if (startup_directory.empty()) {
		fprintf(stderr, "failed to determine current working directory: %s\n", strerror(errno));
		return 1;
	}

	Option opt;
	bool check_config = false;
	if (!parse_option(argc, argv, startup_directory, &opt, &check_config) || !validate_configuration(&opt, startup_directory)) {
		return 1;
	}
	if (check_config) {
		printf("configuration is valid\n");
		return 0;
	}

	Logger::start();
	Logger::pause(true);
	logprintf(LOG_DEFAULT, "=== Starting BEHIND DNS Server ===\n");
	for (int i = 1; i < argc; i++) {
		logprintf(LOG_DEFAULT, "argv[%d] = %s\n", i, argv[i]);
	}

	int exit_code = 0;
	std::optional<Option> fallback_option;
	std::optional<Option> reload_candidate;
	std::future<std::optional<Option>> reload_validation;
	bool validate_again = false;
	auto ValidationReady = [&]() {
		return reload_validation.valid() && reload_validation.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
	};
	auto StartValidation = [&]() {
		logprintf(LOG_DEFAULT, "=== SIGHUP: validating candidate asynchronously ===\n");
		try {
			reload_validation = std::async(std::launch::async,
				[argc, argv, startup_directory]() -> std::optional<Option> {
					try {
						Option candidate;
						bool ignored_check_config = false;
						if (parse_option(argc, argv, startup_directory, &candidate,
								&ignored_check_config)
							&& validate_configuration(&candidate, startup_directory)) {
							return candidate;
						}
					} catch (std::exception const &e) {
						fprintf(stderr, "configuration reload validation failed: %s\n", e.what());
					} catch (...) {
						fprintf(stderr, "configuration reload validation failed: unknown exception\n");
					}
					return std::nullopt;
				});
		} catch (std::exception const &e) {
			logprintf(LOG_BOTH,
				"cannot start configuration validation; keeping current runtime: %s\n",
				e.what());
		}
	};
	auto ValidateReload = [&](bool requested) {
		if (requested) {
			if (reload_validation.valid() && !ValidationReady()) {
				validate_again = true;
				logprintf(LOG_DEFAULT,
					"configuration validation already running; queued another validation\n");
				return false;
			}
			if (reload_validation.valid()) {
				try {
					(void)reload_validation.get();
				} catch (...) {
				}
			}
			validate_again = false;
			StartValidation();
			return false;
		}
		if (!ValidationReady()) return false;

		std::optional<Option> candidate;
		try {
			candidate = reload_validation.get();
		} catch (std::exception const &e) {
			logprintf(LOG_BOTH, "configuration reload validation failed: %s\n", e.what());
		} catch (...) {
			logprintf(LOG_BOTH, "configuration reload validation failed: unknown exception\n");
		}
		if (validate_again) {
			validate_again = false;
			StartValidation();
			return false;
		}
		if (candidate) {
			reload_candidate = std::move(*candidate);
			logprintf(LOG_DEFAULT, "configuration reload validated; applying candidate\n");
			return true;
		}
		reload_candidate.reset();
		logprintf(LOG_BOTH,
			"configuration reload failed validation; keeping current runtime\n");
		return false;
	};
	while (1) {
		reload_candidate.reset();
		bool ok = main2(opt, startup_directory, ValidateReload);
		if (!ok) {
			if (fallback_option) {
				opt = std::move(*fallback_option);
				fallback_option.reset();
				logprintf(LOG_BOTH, "reloaded configuration failed at runtime; restored previous configuration\n");
				continue;
			}
			exit_code = 1;
			break;
		}

		if (reload_candidate) {
			fallback_option = opt;
			opt = std::move(*reload_candidate);
			reload_candidate.reset();
			continue;
		}
		fallback_option.reset(); // the active configuration ran successfully
		if (sigint_caught.load(std::memory_order_relaxed)) {
			logprintf(LOG_DEFAULT, "=== SIGINT ===\n");
		}
		break;
	}

	if (reload_validation.valid()) {
		logprintf(LOG_DEFAULT, "waiting for configuration validation to finish during shutdown\n");
		if (reload_validation.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
			static constexpr char message[] = "configuration validation did not stop within 5 seconds; forcing shutdown\n";
			(void)::write(STDERR_FILENO, message, sizeof(message) - 1);
			_exit(exit_code);
		}
		try {
			(void)reload_validation.get();
		} catch (...) {
		}
	}
	Logger::stop();

	return exit_code;
}
