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
	std::string r;
	r.resize(s.size());
	for (size_t i = 0; i < s.size(); i++) {
		r[i] = (char)std::tolower((unsigned char)s[i]);
	}
	return r;
}

