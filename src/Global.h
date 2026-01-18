#ifndef GLOBAL_H
#define GLOBAL_H

#include <string>

struct Global {
	std::string log_file = "/var/log/behind/behind.log";
};

extern Global *global;

#endif // GLOBAL_H
