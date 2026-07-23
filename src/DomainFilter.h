#ifndef DOMAINFILTER_H
#define DOMAINFILTER_H

#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

class DomainFilter {
public:
	enum Kind {
		NORMAL,
		NXDOMAIN,
		NODATA,
		NODATA_AAAA,
	};

private:
	struct Item {
		std::string name;
		Kind kind = NORMAL;
	};
	struct RegexItem {
		std::regex expression;
		Kind kind = NORMAL;
	};
	std::unordered_map<std::string, std::vector<Item>> suffix_map_;
	std::unordered_map<std::string, std::vector<Item>> prefix_map_;
	std::vector<Item> middle_map_;
	std::vector<RegexItem> regex_list_;
	size_t entry_count_ = 0;
	bool add_entry(std::string const &name, Kind kind, std::string *error);

public:
	Kind find(std::string const &name) const;
	bool add_nxdomain(std::string const &name, std::string *error = nullptr);
	bool add_nodata(std::string const &name, std::string *error = nullptr);
	bool add_nodata_aaaa(std::string const &name, std::string *error = nullptr);
};

#endif // DOMAINFILTER_H
