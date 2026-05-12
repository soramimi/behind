#ifndef DOMAINFILTER_H
#define DOMAINFILTER_H

#include <vector>
#include <string>
#include <unordered_map>

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
	std::unordered_map<std::string, std::vector<Item>> suffix_map_;
	std::unordered_map<std::string, std::vector<Item>> prefix_map_;
	std::vector<Item> middle_map_;
	std::vector<Item> regex_list_;
	void add_entry(std::string const &name, Kind kind);
public:
	Kind find(std::string const &name) const;
	void add_nxdomain(std::string const &name);
	void add_nodata(std::string const &name);
	void add_nodata_aaaa(std::string const &name);
};

#endif // DOMAINFILTER_H
