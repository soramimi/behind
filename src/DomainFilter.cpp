#include "DomainFilter.h"
#include "misc.h"
#include <cctype>
#include <chrono>
#include <cstring>

namespace {

bool fail(std::string *error, std::string message)
{
	if (error) {
		*error = std::move(message);
	}
	return false;
}

// Extract the literal runs of a regular expression, treating a backslash escape
// of an ordinary character as that character, so "doubleclick\.net" yields the
// single literal "doubleclick.net".
std::vector<std::string> regex_literal_runs(std::string const &pattern)
{
	std::vector<std::string> runs;
	std::string literal;
	auto Flush = [&]() {
		if (literal.size() >= 3) runs.push_back(literal);
		literal.clear();
	};
	auto IsLiteral = [](unsigned char c) {
		return isalnum(c) || c == '-' || c == '.';
	};
	for (size_t i = 0; i < pattern.size(); i++) {
		unsigned char c = (unsigned char)pattern[i];
		if (c == '\\' && i + 1 < pattern.size() && IsLiteral((unsigned char)pattern[i + 1])) {
			literal.push_back(pattern[++i]);
		} else if (IsLiteral(c)) {
			literal.push_back((char)c);
		} else {
			Flush();
		}
	}
	Flush();
	return runs;
}

// A filter regex is evaluated against every query name, so a pattern with
// catastrophic backtracking lets a single query packet stall the whole
// single-threaded event loop indefinitely.  libstdc++'s std::regex has no
// complexity or step limit and never throws for this, so catching
// std::regex_error at match time is not a defense.  Since the regex engine must
// be kept, the only effective defense is to reject such a pattern when it is
// loaded, which also makes it visible to --check-config.
//
// Cost grows exponentially in the input length for exactly the patterns worth
// rejecting, so probing with slowly growing lengths detects the blow-up while
// every individual match is still cheap: a pattern that needs 20 s at 63 bytes
// needs well under a millisecond at 16 bytes.  The step must stay small, because
// the budget can only be checked between matches and a single regex_match cannot
// be interrupted: with a base-2 blow-up, a step of 2 bounds the cost of the
// match that finally trips the budget to roughly 4x the budget.
bool regex_is_too_expensive(std::regex const &expression, std::string const &pattern)
{
	using Clock = std::chrono::steady_clock;
	// Generous enough that a linear pattern's few thousand cheap probe matches
	// never trip it: rejecting a legitimate rule would break the operator's
	// config, so false positives matter more here than a slow load.
	constexpr double BUDGET_MS = 200.0;
	constexpr size_t MAX_NAME = 253; // decode_name() never produces a longer name

	// The worst case for a nested-quantifier pattern is an input that almost
	// matches: the engine must explore every decomposition before it can fail.
	// Derive such inputs from the pattern's own literals, with the final
	// character changed so the match fails at the very end.
	std::vector<std::string> tails = regex_literal_runs(pattern);
	for (std::string &tail : tails) {
		tail.back() = tail.back() == 'z' ? 'y' : 'z';
	}
	tails.emplace_back();
	// A pattern such as (a|a?)+$ only blows up on input it cannot match, and
	// every probe above would happily match. '~' is accepted inside a label by
	// decode_name(), so this is a byte a client can really send.
	tails.emplace_back("~");

	// The filler alphabet has to come from the characters the pattern itself
	// mentions: a blow-up only happens on input the quantified groups can match,
	// so a fixed alphabet would miss patterns like (x|xx)+y.
	std::vector<std::string> fillers = { "a", "a.", "ab", "a-", "0" };
	{
		std::string seen;
		for (size_t i = 0; i < pattern.size() && seen.size() < 6; i++) {
			unsigned char c = (unsigned char)pattern[i];
			if (c == '\\' && i + 1 < pattern.size()) c = (unsigned char)pattern[++i];
			if (!isalnum(c) && c != '-') continue;
			if (seen.find((char)c) != std::string::npos) continue;
			seen.push_back((char)c);
			fillers.push_back(std::string(1, (char)c));
			fillers.push_back(std::string(1, (char)c) + ".");
		}
	}

	Clock::time_point const started = Clock::now();
	auto Elapsed = [&]() {
		return std::chrono::duration<double, std::milli>(Clock::now() - started).count();
	};
	for (size_t length = 8; length <= MAX_NAME; length += 3) {
		for (std::string const &filler : fillers) {
			std::string filling;
			while (filling.size() < length) filling += filler;
			filling.resize(length);
			for (std::string const &tail : tails) {
				std::string probe = filling + tail;
				if (probe.size() > MAX_NAME) probe.resize(MAX_NAME);
				try {
					(void)std::regex_match(probe, expression);
				} catch (std::regex_error const &) {
					return true; // the engine already hit a resource limit
				}
				if (Elapsed() > BUDGET_MS) return true;
			}
		}
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
	return { };
}

DomainFilter::Kind DomainFilter::find(std::string const &name) const
{
	std::string loname = misc::strtolower(name);
	// suffix match
	{
		auto Find = [&](std::string const &name) {
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
		for (auto const &item : middle_map_) {
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
	auto Success = [&]() {
		entry_count_++;
		return true;
	};

	std::string loname = misc::strtolower(name);

	if (name.size() >= 2 && name.front() == '/' && name.back() == '/') {
		std::string pattern = name.substr(1, name.size() - 2);
		if (pattern.empty()) {
			return fail(error, "regular expression must not be empty");
		}
		// Every regex rule is evaluated on every query that reaches the filter, so
		// the count is bounded far more tightly than the overall rule count.
		if (regex_count_ >= MAX_REGEX_RULES) {
			return fail(error, "too many regular-expression filter rules (maximum " + std::to_string(MAX_REGEX_RULES) + ")");
		}
		try {
			RegexItem item;
			item.kind = kind;
			item.expression = std::regex(pattern, std::regex_constants::ECMAScript | std::regex_constants::icase);
			if (regex_is_too_expensive(item.expression, pattern)) {
				return fail(error, "regular expression is too expensive to evaluate safely"
									" (it backtracks catastrophically, so one query could stall the server);"
									" prefer the *.example.com, example.com.* or *example* forms");
			}
			regex_list_.push_back(std::move(item));
			regex_count_++;
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
