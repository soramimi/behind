#ifndef MISC_H
#define MISC_H

#include <cstdint>
#include <string>
#include <string_view>

namespace misc {

uint64_t get_tick_count();

std::string strtolower(std::string_view const &s);

}

#endif // MISC_H
