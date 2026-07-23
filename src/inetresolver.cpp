#include "inetresolver.h"
#include "Logger.h"
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <WS2tcpip.h>
#include <windows.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

bool InetResolver::resolve(const char *name, Type type, Addr *out)
{
	if (!name || !out) return false;
	out->type = UNSPEC;
	out->addr.clear();
	struct addrinfo hints = { };
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = type == IN4 ? AF_INET : type == IN6 ? AF_INET6
														  : AF_UNSPEC;
	struct addrinfo *result = nullptr;
	int error = getaddrinfo(name, nullptr, &hints, &result);
	if (error != 0) {
		logprintf(LOG_DEFAULT, "resolve %s: %s\n", name, gai_strerror(error));
		return false;
	}
	for (struct addrinfo *item = result; item; item = item->ai_next) {
		if (item->ai_family == AF_INET && item->ai_addrlen >= sizeof(sockaddr_in)) {
			auto *address = (sockaddr_in *)item->ai_addr;
			out->add_in4(&address->sin_addr);
			break;
		}
		if (item->ai_family == AF_INET6 && item->ai_addrlen >= sizeof(sockaddr_in6)) {
			auto *address = (sockaddr_in6 *)item->ai_addr;
			out->add_in6(&address->sin6_addr);
			break;
		}
	}
	freeaddrinfo(result);
	return !out->empty();
}

void InetResolver::Addr::add_in4(const _in_addr *a)
{
	type = IN4;
	std::vector<uint8_t> vec(4);
	memcpy(vec.data(), a, 4);
	addr.push_back(vec);
}

void InetResolver::Addr::add_in6(const _in6_addr *a)
{
	type = IN6;
	std::vector<uint8_t> vec(16);
	memcpy(vec.data(), a, 16);
	addr.push_back(vec);
}

std::string InetResolver::Addr::to_string(size_t i) const
{
	if (i < addr.size()) {
		char buf[INET6_ADDRSTRLEN];
		if (type == InetResolver::IN4) {
			struct in_addr *in4 = (struct in_addr *)addr[i].data();
			if (inet_ntop(AF_INET, in4, buf, sizeof(buf))) {
				return buf;
			}
		} else if (type == InetResolver::IN6) {
			struct in6_addr *in6 = (struct in6_addr *)addr[i].data();
			if (inet_ntop(AF_INET6, in6, buf, sizeof(buf))) {
				return buf;
			}
		}
	}
	return { };
}
