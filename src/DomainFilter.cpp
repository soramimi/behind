#include "DomainFilter.h"
#include "misc.h"
#include <cstring>

namespace {

bool fail(std::string *error, std::string message)
{
	if (error) {
		*error = std::move(message);
	}
	return false;
}

}

std::string domain_suffix_key(std::string const &name)
{
	static struct KnownSuffix {
		std::vector<std::string> vec;
		KnownSuffix()
		{
			vec.push_back("lan");
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
	for (RegexItem const &item : regex_list_) {
		try {
			if (std::regex_match(loname, item.expression)) {
				return item.kind;
			}
		} catch (std::regex_error const &) {
			// A deny/filter rule must never become fail-open because the regex engine
			// hit a run-time resource/complexity error.
			return item.kind;
		}
	}
	return NORMAL;
}

bool DomainFilter::add_entry(std::string const &name, Kind kind, std::string *error)
{
	if (name.empty()) {
		return fail(error, "filter value must not be empty");
	}
	if (entry_count_ >= 100000) {
		return fail(error, "too many filter rules (maximum 100000)");
	}
	if (name.size() > 4096) {
		return fail(error, "filter rule is too long (maximum 4096 bytes)");
	}
	auto Success = [&](){
		entry_count_++;
		return true;
	};

	std::string loname = misc::strtolower(name);

	if (name.size() >= 2 && name.front() == '/' && name.back() == '/') {
		std::string pattern = name.substr(1, name.size() - 2);
		if (pattern.empty()) {
			return fail(error, "regular expression must not be empty");
		}
		try {
			RegexItem item;
			item.kind = kind;
			item.expression = std::regex(pattern,
				std::regex_constants::ECMAScript | std::regex_constants::icase);
			regex_list_.push_back(std::move(item));
			return Success();
		} catch (std::regex_error const &e) {
			return fail(error, std::string("invalid regular expression: ") + e.what());
		}
	}

	if (loname.size() >= 2 && loname.front() == '*' && loname.back() == '*') {
		std::string needle = loname.substr(1, loname.size() - 2);
		if (needle.empty()) {
			return fail(error, "middle-match filter must not be empty");
		}
		Item item;
		item.kind = kind;
		item.name = std::move(needle);
		middle_map_.push_back(std::move(item));
		return Success();
	}

	if (loname.size() >= 3 && loname.compare(loname.size() - 2, 2, ".*") == 0) {
		std::string prefix = loname.substr(0, loname.size() - 1);
		if (prefix == "." || !misc::is_valid_domain(prefix)) {
			return fail(error, "invalid prefix-match domain");
		}
		std::string key = domain_prefix_key(loname);
		if (key.empty()) {
			return fail(error, "invalid prefix-match domain");
		}
		Item item;
		item.kind = kind;
		item.name = std::move(prefix);
		auto it = prefix_map_.find(key);
		if (it == prefix_map_.end()) {
			it = prefix_map_.insert(it, std::make_pair(key, std::vector<Item>()));
		}
		it->second.push_back(std::move(item));
		return Success();
	}

	{
		// suffix match
		Item item;
		item.kind = kind;
		if (loname.size() >= 2 && loname[0] == '*' && loname[1] == '.') {
			item.name = loname.substr(2);
		} else {
			item.name = loname;
		}
		if (!misc::is_valid_domain(item.name)) {
			return fail(error, "invalid filter domain or wildcard pattern");
		}
		std::string key = domain_suffix_key(loname);
		if (!key.empty()) {
			auto it = suffix_map_.find(key);
			if (it == suffix_map_.end()) {
				it = suffix_map_.insert(it, std::make_pair(key, std::vector<Item>()));
			}
			it->second.push_back(std::move(item));
			return Success();
		}
	}
	return fail(error, "invalid filter domain");
}

bool DomainFilter::add_nxdomain(std::string const &name, std::string *error)
{
	return add_entry(name, Kind::NXDOMAIN, error);
}

bool DomainFilter::add_nodata(const std::string &name, std::string *error)
{
	return add_entry(name, Kind::NODATA, error);
}

bool DomainFilter::add_nodata_aaaa(const std::string &name, std::string *error)
{
	return add_entry(name, Kind::NODATA_AAAA, error);
}
