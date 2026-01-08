#ifndef MISC_H
#define MISC_H

#include <cstdint>
#include <string>
#include <string_view>

namespace misc {

uint64_t get_tick_count();

std::string strtolower(std::string_view const &s);

std::string trimmed(char const *begin, char const *end);

}

#endif // MISC_H
