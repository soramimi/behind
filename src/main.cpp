
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

struct Option {
	// bool daemon = false;
};

void apply_option(int argc, char **argv, Behind *ns, Option *opt)
{
	bool verbose = false;
	*opt = {};

	for (int i = 1; i < argc; i++) {
		char const *arg = argv[i];
		if (arg[0] == '-') {
			// if (strcmp(arg, "-D") == 0 || strcmp(arg, "--daemon") == 0) {
			// 	opt->daemon = true;
			// }
		}
	}
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

	Behind ns;
	Option opt;
	apply_option(argc, argv, &ns, &opt);
	main2(&ns, &opt);

	return 0;
}

