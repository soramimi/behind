#include "DomainFilter.h"
#include "misc.h"
#include <regex>
#include <cstring>

DomainFilter::Kind DomainFilter::find(const std::string &name) const
{
	std::string key = misc::strtolower(name);
	for (std::string const &nxdomain : nxdomain_) {
		if (nxdomain.size() > 2) {
			if (nxdomain[0] == '/' && nxdomain[nxdomain.size() - 1] == '/') {
				std::string pattern = nxdomain.substr(1, nxdomain.size() - 2);
				if (std::regex_match(key, std::regex(pattern))) {
					return NXDOMAIN;
				}
			} else if (nxdomain[0] == '*' || nxdomain[1] == '.') {
				size_t n = nxdomain.size() - 1;
				if (key.size() > n && memcmp(key.c_str() + key.size() - n, nxdomain.c_str() + 1, n) == 0) {
					return NXDOMAIN;
				}
				if (strcmp(key.c_str(), nxdomain.c_str() + 2) == 0) {
					return NXDOMAIN;
				}
			} else if (nxdomain[nxdomain.size() - 1] == '*' || nxdomain[nxdomain.size() - 2] == '.') {
				size_t n = nxdomain.size() - 1;
				if (key.size() > n && memcmp(key.c_str(), nxdomain.c_str(), n) == 0) {
					return NXDOMAIN;
				}
			} else if (key == nxdomain) {
				return NXDOMAIN;
			}
		}
	}
	return NORMAL;
}

void DomainFilter::add_nxdomain(const std::string &name)
{
	nxdomain_.push_back(misc::strtolower(name));
}

