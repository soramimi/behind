#ifndef MISC_H
#define MISC_H

#include <cstdint>
#include <string>
#include <string_view>

namespace misc {

uint64_t get_tick_count();

std::string strtolower(std::string_view const &s);

std::string trimmed(char const *begin, char const *end);

std::string realpath(char const *path);
std::string realpath(std::string const &path);

size_t parse_int(char const *p, int *out);

}

#endif // MISC_H
