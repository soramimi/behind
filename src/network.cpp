
#include <vector>
#include "network.h"

#include <stdint.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>

std::string get_host_name()
{
	char tmp[300];
	int i = sizeof(tmp) - 1;
	tmp[i] = 0;
	gethostname(tmp, i);
	return tmp;
}

