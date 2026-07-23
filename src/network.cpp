
#include "network.h"
#include <vector>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

std::string get_host_name()
{
	char tmp[300];
	int i = sizeof(tmp) - 1;
	tmp[i] = 0;
	gethostname(tmp, i);
	return tmp;
}
