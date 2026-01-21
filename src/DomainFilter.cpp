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

std::string domain_prefix_key(std::string const &name)
{
	char const *p = strchr(name.c_str(), '.');
	if (p) {
		return name.substr(0, p + 1 - name.c_str());
	}
	return {};
}

DomainFilter::Kind DomainFilter::find(std::string const &name) const
{
	std::string loname = misc::strtolower(name);
	{
		std::string key = domain_suffix_key(loname);
		if (!key.empty()) {
			auto it = suffix_map_.find(key);
			if (it != suffix_map_.end()) {
				for (Item const &item : it->second) {
					if (item.name == loname) return item.kind;
					const size_t n = item.name.size();
					if (n < loname.size()) {
						char const *p = loname.c_str() + loname.size() - n;
						if (memcmp(p, item.name.c_str(), n) == 0 && p[-1] == '.') {
							return item.kind;
						}
					}
				}
			}
		}
	}
	{
		std::string key = domain_prefix_key(loname);
		if (!key.empty()) {
			auto it = prefix_map_.find(key);
			if (it != prefix_map_.end()) {
				for (Item const &item : it->second) {
					if (strncmp(loname.c_str(), item.name.c_str(), item.name.size()) == 0) {
						return item.kind;
					}
				}
			}
		}
	}
	for (Item const &item : regex_list_) {
		if (std::regex_match(loname, std::regex(item.name))) {
			return item.kind;
		}
	}
	return NORMAL;
}

void DomainFilter::add_nxdomain(std::string const &name)
{
	std::string loname = misc::strtolower(name);
	if (loname.size() > 2) {
		if (loname[0] == '/' && loname[loname.size() - 1] == '/') {
			// regex match
			Item item;
			item.kind = NXDOMAIN;
			item.name = loname.substr(1, loname.size() - 2);
			regex_list_.push_back(item);
			return;
		}
		if (loname[loname.size() - 2] == '.' && loname[loname.size() - 1] == '*') {
			// prefix match
			std::string key = domain_prefix_key(loname);
			Item item;
			item.kind = NXDOMAIN;
			item.name = loname.substr(0, loname.size() - 1);
			auto it = prefix_map_.find(key);
			if (it == prefix_map_.end()) {
				it = prefix_map_.insert(it, std::make_pair(key, std::vector<Item>()));
			}
			it->second.push_back(item);
			return;
		}
	}
	{
		// suffix match
		Item item;
		item.kind = NXDOMAIN;
		if (loname[0] == '*' || loname[1] == '.') {
			item.name = loname.substr(2);
		} else {
			item.name = loname;
		}
		std::string key = domain_suffix_key(loname);
		if (!key.empty()) {
			auto it = suffix_map_.find(key);
			if (it == suffix_map_.end()) {
				it = suffix_map_.insert(it, std::make_pair(key, std::vector<Item>()));
			}
			it->second.push_back(item);
			return;
		}
	}
}

