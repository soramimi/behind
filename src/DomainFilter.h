#ifndef DOMAINFILTER_H
#define DOMAINFILTER_H

#include <vector>
#include <string>

class DomainFilter {
private:
	std::vector<std::string> nxdomain_;
public:
	enum Kind {
		NORMAL,
		NXDOMAIN,
	};
	Kind find(const std::string &name) const;
	void add_nxdomain(const std::string &name);
};

#endif // DOMAINFILTER_H
