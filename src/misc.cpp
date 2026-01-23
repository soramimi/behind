#include "misc.h"
#include <stdlib.h>
#include <limits.h>
#include <chrono>
#include <cstdio>
#include <cstdarg>

std::string misc::asprintf(char const *fmt, ...)
{
	std::string s;
	va_list ap;
	va_start(ap, fmt);
	char *p = nullptr;
	::vasprintf(&p, fmt, ap);
	va_end(ap);
	if (p) {
		s = p;
		free(p);
	}
	return s;
}

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

std::string misc::realpath(const char *path)
{
	char tmp[PATH_MAX];
	if (::realpath(path, tmp)) {
		return tmp;
	}
	return {};
}

std::string misc::realpath(std::string const &path)
{
	return realpath(path.c_str());
}

size_t misc::parse_int(char const *p, int *out)
{
	unsigned long int val = 0;
	size_t i = 0;
	while (p[i]) {
		int c = (unsigned char)p[i];
		if (!isdigit(c)) break;
		val = val * 10 + (c - '0');
		if (val > std::numeric_limits<int>::max()) {
			return 0;
		}
		i++;
	}
	*out = (int)val;
	return i;
}

