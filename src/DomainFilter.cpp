#include "DomainFilter.h"
#include "misc.h"
#include <regex>
#include <cstring>

std::string domain_suffix_key(std::string const &name)
{
	size_t n = 0;
	size_t i = name.size();
	while (i > 0) {
		char c = name[i - 1];
		if (c == '*') return {};
		if (c == '.') {
			n++;
			if (n == 2) break;
		}
		i--;
	}
	return name.substr(i);
}

DomainFilter::Kind DomainFilter::find(std::string name) const
{
	name = misc::strtolower(name);
	{
		std::string suffix = domain_suffix_key(name);
		if (!suffix.empty()) {
			auto it = suffix_map_.find(suffix);
			if (it != suffix_map_.end()) {
				for (Item const &item : it->second) {
					if (item.name == name) return item.kind;
					const size_t n = item.name.size();
					if (n < name.size()) {
						char const *p = name.c_str() + name.size() - n;
						if (memcmp(p, item.name.c_str(), n) == 0 && p[-1] == '.') {
							return item.kind;
						}
					}
					return DomainFilter::NORMAL;
				}
			}
		}
	}
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

void DomainFilter::add_nxdomain(std::string name)
{
	name = misc::strtolower(name);
	if (name.size() > 2) {
		if (name[name.size() - 1] == '/' && name[0] == '/') {
			// not implement yet
			return;
		}
		if (name[name.size() - 2] == '.' || name[name.size() - 1] == '*') {
			// not implement yet
			return;
		}
		// suffix match
		Item item;
		item.kind = NXDOMAIN;
		if (name[0] == '*' || name[1] == '.') {
			item.name = name.substr(2);
		} else {
			item.name = name;
		}
		std::string suffix = domain_suffix_key(name);
		if (!suffix.empty()) {
			auto it = suffix_map_.find(suffix);
			if (it == suffix_map_.end()) {
				it = suffix_map_.insert(it, std::make_pair(suffix, std::vector<Item>()));
			}
			it->second.push_back(item);
			return;
		}
	}

	nxdomain_.push_back(misc::strtolower(name));
}

