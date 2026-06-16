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

std::string_view misc::unquote(std::string_view s)
{
	if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
		s.remove_prefix(1);
		s.remove_suffix(1);
	}
	return s;
}

std::string misc::unquote(std::string s)
{
	if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
		s = s.substr(1, s.size() - 2);
	}
	return s;
}

std::string misc::strtolower(std::string_view const &s)
{
	std::string r(s);
	for (size_t i = 0; i < r.size(); i++) {
		r[i] = (char)std::tolower((unsigned char)r[i]);
	}
	return r;
}

std::string_view misc::trimmed(std::string_view const &sv)
{
	char const *begin = sv.data();
	char const *end = begin + sv.size();
	char const *left = begin;
	char const *right = end;
	while (left < right && isspace((unsigned char)*left)) left++;
	while (left < right && isspace((unsigned char)right[-1])) right--;
	return {left, right - left};
}

std::vector<std::string_view> misc::split(char const *begin, char const *end)
{
	char const *left = begin;
	char const *right = begin;
	char const *ptr = begin;
	std::vector<std::string_view> r;
	int quote = 0;
	while (1) {
		int c = 0;
		char const *next = ptr;
		if (ptr < end) {
			c = (unsigned char)*ptr;
			next++;
		}
		if (quote) {
			if (c == quote) {
				quote = 0;
			} else if (c == 0) {
				break;
			}
			right = ptr = next;
		} else if (!quote && (c == '"')) {
			quote = c;
		} else if (c == 0 || isspace(c)) {
			if (left < right) {
				r.emplace_back(left, right - left);
			}
			if (c == 0) {
				break;
			}
			left = right = next;
		} else {
			right = next;
		}
		ptr = next;
	}
	return r;
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

bool misc::is_valid_domain(std::string_view const &s)
{
	if (s.empty()) return false;
	if (s == ".") return true; // root

	std::string_view v = s;
	if (v.back() == '.') {
		v.remove_suffix(1);
	}
	if (v.empty()) return false;
	if (v.size() > 253) return false;
	if (v.front() == '.' || v.back() == '.') return false;

	size_t label_len = 0;
	for (size_t i = 0; i < v.size(); i++) {
		char c = v[i];
		if (c == '.') {
			if (label_len == 0 || label_len > 63) return false;
			label_len = 0;
		} else {
			if (!(isalnum((unsigned char)c) || c == '-' || c == '_')) return false;
			if (label_len == 0 && c == '-') return false; // label cannot start with '-'
			label_len++;
			if (label_len > 63) return false;
		}
	}
	if (label_len == 0 || label_len > 63) return false;
	return true;
}

