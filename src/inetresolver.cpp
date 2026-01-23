#include "inetresolver.h"
#include "Logger.h"
#include <cstdio>
#include <cstring>


#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <WS2tcpip.h>
#else
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif


bool InetResolver::resolve(const char *name, Type type, Addr *out)
{
	if (!name || !out) return false;

	if (type == InetResolver::IN4) {
		out->type = type;
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_INET;
		struct addrinfo *res = nullptr;
		int err = getaddrinfo(name, NULL, &hints, &res);
		if (err != 0) {
			logprintf(LOG_DEFAULT, "error %d\n", err);
			return false;
		}
		for (struct addrinfo *p = res; p; p = p->ai_next) {
			struct sockaddr_in *addr = (struct sockaddr_in *)p->ai_addr;
			std::vector<uint8_t> a(sizeof(in_addr));
			memcpy(a.data(), &addr->sin_addr.s_addr, sizeof(struct in_addr));
			out->addr.push_back(a);
			break;
		}
		freeaddrinfo(res);
	} else if (type == InetResolver::IN6) {
		out->type = type;
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_INET6;
		struct addrinfo *res = nullptr;
		int err = getaddrinfo(name, NULL, &hints, &res);
		if (err != 0) {
			logprintf(LOG_DEFAULT, "error %d\n", err);
			return false;
		}
		for (struct addrinfo *p = res; p; p = p->ai_next) {
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)p->ai_addr;
			std::vector<uint8_t> a(sizeof(in6_addr));
			memcpy(a.data(), addr->sin6_addr.s6_addr, sizeof(struct in6_addr));
			out->addr.push_back(a);
			break;
		}
		freeaddrinfo(res);
	}

	return true;
}

void InetResolver::Addr::add_in4(const _in_addr *a)
{
	std::vector<uint8_t> vec(4);
	memcpy(vec.data(), a, 4);
	addr.push_back(vec);
}

void InetResolver::Addr::add_in6(const _in6_addr *a)
{
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
	return {};
}
