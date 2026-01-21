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
	};
private:
	struct Item {
		std::string name;
		Kind kind = NORMAL;
	};
	std::unordered_map<std::string, std::vector<Item>> suffix_map_;
	std::vector<std::string> nxdomain_;
public:
	Kind find(std::string name) const;
	void add_nxdomain(std::string name);
};

#endif // DOMAINFILTER_H
