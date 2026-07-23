#ifndef __BogusDNS_network_h
#define __BogusDNS_network_h

#include <stdint.h>
#include <string>
#include <vector>

struct netif_t {
	uint32_t addr;
	uint32_t mask;
};

std::string get_host_name();

#endif
