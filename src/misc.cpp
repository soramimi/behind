#include "misc.h"

#include <chrono>

uint64_t misc::get_tick_count()
{
	using clock = std::chrono::steady_clock;

	static const clock::time_point start = clock::now();

	const auto now = clock::now();
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);

	return static_cast<uint64_t>(elapsed.count());
}

std::string misc::strtolower(std::string_view const &s)
{
	std::string r(s);
	for (size_t i = 0; i < r.size(); i++) {
		r[i] = (char)std::tolower((unsigned char)r[i]);
	}
	return r;
}

std::string misc::trimmed(char const *begin, char const *end)
{
	char const *left = begin;
	char const *right = end;
	while (left < right && isspace((unsigned char)*left)) left++;
	while (left < right && isspace((unsigned char)right[-1])) right--;
	return std::string(left, right);
}
