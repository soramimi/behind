#ifndef MISC_H
#define MISC_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace misc {

std::string asprintf(char const *fmt, ...);

uint64_t get_tick_count();

std::string_view unquote(std::string_view s);
std::string unquote(std::string s);
std::string strtolower(std::string_view const &s);

std::string_view trimmed(std::string_view const &sv);
std::vector<std::string_view> split(char const *begin, char const *end);
static inline std::vector<std::string_view> split(std::string_view const &s)
{
	return split(s.data(), s.data() + s.size());
}

std::string realpath(char const *path);
std::string realpath(std::string const &path);

size_t parse_int(char const *p, int *out);

}

#endif // MISC_H
