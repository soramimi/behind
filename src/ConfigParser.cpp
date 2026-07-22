#include "ConfigParser.h"
#include "LineReader.h"
#include "misc.h"
#include <cstdio>
#include <exception>
#include <string_view>

namespace {

bool report_error(std::string const &file, int line, std::string const &message)
{
	if (line > 0) {
		fprintf(stderr, "%s:%d: %s\n", file.c_str(), line, message.c_str());
	} else {
		fprintf(stderr, "%s: %s\n", file.c_str(), message.c_str());
	}
	return false;
}

bool find_comment(std::string_view line, size_t *comment, std::string *error)
{
	char quote = 0;
	for (size_t i = 0; i < line.size(); i++) {
		char c = line[i];
		if (quote) {
			if (c == quote) quote = 0;
		} else if (c == '\'' || c == '"') {
			quote = c;
		} else if (c == ';' || c == '#') {
			*comment = i;
			return true;
		}
	}
	if (quote) {
		*error = "unterminated quoted string";
		return false;
	}
	*comment = line.size();
	return true;
}

size_t find_unquoted(std::string_view text, char wanted, size_t begin = 0)
{
	char quote = 0;
	for (size_t i = begin; i < text.size(); i++) {
		char c = text[i];
		if (quote) {
			if (c == quote) quote = 0;
		} else if (c == '\'' || c == '"') {
			quote = c;
		} else if (c == wanted) {
			return i;
		}
	}
	return std::string_view::npos;
}

}

bool ConfigParser::parse(char const *file, fn_assign_t fn_assign, void *cookie)
{
	LineReader reader;
	if (!reader.open(file)) {
		return report_error(reader.error_file(), reader.error_line(), reader.error_message());
	}
	std::string line;
	std::string section;
	while (reader.getline(&line)) {
		std::string const source_file = reader.file();
		int const source_line = reader.line();
		std::string parse_error;
		size_t comment = 0;
		if (!find_comment(line, &comment, &parse_error)) {
			return report_error(source_file, source_line, parse_error);
		}
		std::string_view content = misc::trimmed(std::string_view(line).substr(0, comment));
		if (content.empty()) continue;
		for (unsigned char c : content) {
			if ((c < 0x20 && c != '\t') || c == 0x7f) {
				return report_error(source_file, source_line,
					"control character is not allowed in configuration text");
			}
		}

		if (content.front() == '[') {
			size_t closing = find_unquoted(content, ']', 1);
			if (closing == std::string_view::npos) {
				return report_error(source_file, source_line, "unterminated section header");
			}
			if (!misc::trimmed(content.substr(closing + 1)).empty()) {
				return report_error(source_file, source_line,
					"unexpected text after section header");
			}
			std::string_view name = misc::trimmed(content.substr(1, closing - 1));
			if (name.empty()) {
				return report_error(source_file, source_line, "section name must not be empty");
			}
			section = std::string(name);
			std::string assignment_error;
			try {
				if (!fn_assign(section, {}, {}, cookie, &assignment_error)) {
					if (assignment_error.empty()) assignment_error = "invalid section";
					return report_error(source_file, source_line, assignment_error);
				}
			} catch (std::exception const &e) {
				return report_error(source_file, source_line,
					std::string("exception while validating section: ") + e.what());
			}
			continue;
		}

		size_t equals = find_unquoted(content, '=');
		if (equals == std::string_view::npos) {
			return report_error(source_file, source_line, "expected a key = value assignment");
		}
		std::string_view key = misc::trimmed(content.substr(0, equals));
		std::string_view value = misc::trimmed(content.substr(equals + 1));
		if (key.empty()) {
			return report_error(source_file, source_line, "option name must not be empty");
		}
		if (!value.empty() && (value.front() == '"' || value.front() == '\'')) {
			char delimiter = value.front();
			size_t const closing = value.find(delimiter, 1);
			if (closing == std::string_view::npos || closing != value.size() - 1) {
				return report_error(source_file, source_line,
					"unexpected text after quoted value");
			}
			value.remove_prefix(1);
			value.remove_suffix(1);
		}

		std::string assignment_error;
		try {
			if (!fn_assign(section, std::string(key), std::string(value), cookie,
					&assignment_error)) {
				if (assignment_error.empty()) assignment_error = "invalid option or value";
				return report_error(source_file, source_line, assignment_error);
			}
		} catch (std::exception const &e) {
			return report_error(source_file, source_line,
				std::string("exception while applying option: ") + e.what());
		}
	}
	if (reader.failed()) {
		return report_error(reader.error_file(), reader.error_line(), reader.error_message());
	}
	return true;
}

void ConfigParser::example()
{
	struct Option {
	};

	Option opt;
	char const *file = "example.ini";
	parse(file, [](std::string const &section, std::string const &key, std::string const &value,
			void *cookie, std::string *error){
		Option *opt = static_cast<Option *>(cookie);
		(void)section;
		(void)key;
		(void)value;
		(void)opt;
		(void)error;
		return true;
	}, &opt);
}
