#include "DomainFilter.h"
#include "misc.h"
#include <regex>
#include <cstring>

std::string domain_suffix_key(std::string const &name)
{
	static struct KnownSuffix {
		std::vector<std::string> vec;
		KnownSuffix()
		{
			vec.push_back("lan");
			vec.push_back("arpa");
			vec.push_back("local");
		}
	} known_suffix;

	std::vector<std::string_view> parts;
	{
		size_t i = 0;
		size_t j = 0;
		while (1) {
			char c = name[j];
			if (c == '.' || c == 0) {
				parts.push_back(std::string_view(name.c_str() + i, j - i));
				if (c == 0) break;
				i = j + 1;
			}
			j++;
		}
		if (parts.size() == 1) {
			parts.insert(parts.begin(), "*");
		}
	}
	std::string key;

	{
		size_t i = parts.size();
		while (i > 0) {
			i--;
			if (!key.empty()) {
				key = '.' + key;
			}
			key = std::string(parts[i]) + key;
			if (i + 2 == parts.size()) break;
		}

		for (std::string const &s : known_suffix.vec) {
			if (key.size() > s.size()) {
				if (strcmp(key.c_str() + key.size() - s.size(), s.c_str()) == 0) {
					size_t i = key.size() - s.size() - 1;
					if (key[i] == '.') {
						key = key.substr(i + 1);
						break;
					}
				}
			}
		}
	}
	return key;
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
	// suffix match
	{
		auto Find = [&](std::string const &name){
			std::string key = domain_suffix_key(name);
			if (!key.empty()) {
				auto it = suffix_map_.find(key);
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
					}
				}
			}
			return NORMAL;
		};
		auto k = Find(loname);
		if (k != NORMAL) return k;
		char const *p = strchr(loname.c_str(), '.');
		if (p) {
			std::string tmpname = "*";
			tmpname += p;
			k = Find(tmpname);
			if (k != NORMAL) return k;
		}
	}
	// prefix match
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
	// middle match
	{
		for (auto const &item: middle_map_) {
			if (strstr(loname.c_str(), item.name.c_str())) {
				return item.kind;
			}
		}
	}
	// regex match
	for (Item const &item : regex_list_) {
		if (std::regex_match(loname, std::regex(item.name))) {
			return item.kind;
		}
	}
	return NORMAL;
}

void DomainFilter::add_entry(std::string const &name, Kind kind)
{
	std::string loname = misc::strtolower(name);
	if (loname.size() > 2) {
		if (loname[0] == '/' && loname[loname.size() - 1] == '/') {
			// regex match
			Item item;
			item.kind = kind;
			item.name = loname.substr(1, loname.size() - 2);
			regex_list_.push_back(item);
			return;
		}
		if (loname[0] == '*' && loname[loname.size() - 1] == '*') {
			// middle match
			Item item;
			item.kind = kind;
			item.name = loname.substr(1, loname.size() - 2);
			middle_map_.push_back(item);
			return;
		}
		if (loname[loname.size() - 2] == '.' && loname[loname.size() - 1] == '*') {
			// prefix match
			std::string key = domain_prefix_key(loname);
			Item item;
			item.kind = kind;
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
		item.kind = kind;
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

void DomainFilter::add_nxdomain(std::string const &name)
{
	add_entry(name, Kind::NXDOMAIN);
}

void DomainFilter::add_nodata_aaaa(const std::string &name)
{
	add_entry(name, Kind::NODATA_AAAA);
}

