
#include "LineReader.h"
#include "misc.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

LineReader::File *LineReader::current()
{
	return &files_.back();
}

void LineReader::close_all()
{
	for (size_t i = files_.size(); i > 0; i--) {
		File const &file = files_[i - 1];
		::close(file.fd);
	}
	files_.clear();
}

void LineReader::close_one()
{
	if (!files_.empty()) {
		::close(files_.back().fd);
		files_.pop_back();
	}
}

void LineReader::set_error(std::string file, int line, std::string message)
{
	error_file_ = std::move(file);
	error_line_ = line;
	error_message_ = std::move(message);
}

bool LineReader::internal_getline(std::string *out)
{
	constexpr size_t MAX_LINE_SIZE = 1024 * 1024;
	constexpr size_t MAX_TOTAL_SIZE = 64 * 1024 * 1024;
	File *f = nullptr;
	std::string line;
	while (1) {
		if (files_.empty()) return false;
		f = current();
		if (f->length > 0) {
			if (f->last_char == '\r') {
				if (f->buffer[f->offset] == '\n') {
					f->offset++;
					f->length--;
				}
				f->last_char = 0;
			}
			std::string_view v(f->buffer + f->offset, f->length);
			auto i = v.find_first_of("\r\n");
			if (i != std::string_view::npos) {
				f->last_char = v[i];
				if (i > MAX_LINE_SIZE - std::min(line.size(), MAX_LINE_SIZE)) {
					set_error(f->path, f->line + 1, "configuration line exceeds 1 MiB");
					return false;
				}
				line += std::string(v.substr(0, i));
				i++;
				f->offset += i;
				f->length -= i;
				break;
			}
			if (v.size() > MAX_LINE_SIZE - std::min(line.size(), MAX_LINE_SIZE)) {
				set_error(f->path, f->line + 1, "configuration line exceeds 1 MiB");
				return false;
			}
			line += v;
		} else if (f->eof) {
			close_one();
			continue;
		}
		f->offset = 0;
		f->length = 0;
		ssize_t n;
		do {
			n = read(f->fd, f->buffer, sizeof(f->buffer));
		} while (n < 0 && errno == EINTR);
		if (n < 0) {
			set_error(f->path, f->line + 1,
				std::string("failed to read configuration file: ") + strerror(errno));
			return false;
		}
		if (n == 0) {
			f->eof = true;
			break;
		}
		if ((size_t)n > MAX_TOTAL_SIZE - std::min(bytes_read_, MAX_TOTAL_SIZE)) {
			set_error(f->path, f->line + 1, "configuration input exceeds 64 MiB");
			return false;
		}
		bytes_read_ += (size_t)n;
		f->length = static_cast<size_t>(n);
	}
	if (out) {
		*out = line;
	}
	f->line++;
	return true;
}

LineReader::LineReader() = default;

LineReader::~LineReader()
{
	close_all();
}

std::string LineReader::file() const
{
	if (files_.empty()) return { };
	return files_.back().path;
}

int LineReader::line() const
{
	if (files_.empty()) return 0;
	return files_.back().line;
}

bool LineReader::failed() const
{
	return !error_message_.empty();
}

std::string const &LineReader::error_file() const
{
	return error_file_;
}

int LineReader::error_line() const
{
	return error_line_;
}

std::string const &LineReader::error_message() const
{
	return error_message_;
}

bool LineReader::open(const std::string &path)
{
	if (path.empty()) {
		set_error(path, 0, "configuration path must not be empty");
		return false;
	}

	errno = 0;
	std::string abspath = misc::realpath(path);
	if (abspath.empty()) {
		int error_number = errno;
		if (error_number == 0) error_number = ENOENT;
		set_error(path, 0, std::string("cannot open configuration file: ") + strerror(error_number));
		return false;
	}
	// guard against runaway / cyclic include chains
	constexpr size_t MAX_INCLUDE_DEPTH = 16;
	constexpr size_t MAX_INCLUDED_FILES = 10000;
	if (files_opened_ >= MAX_INCLUDED_FILES) {
		set_error(path, 0, "included file count exceeds 10000");
		return false;
	}
	if (files_.size() >= MAX_INCLUDE_DEPTH) {
		set_error(abspath, 0, "include depth limit exceeded");
		return false;
	}
	for (File const &f : files_) {
		if (f.path == abspath) {
			set_error(abspath, 0, "cyclic include detected");
			return false;
		}
	}
	// Configuration/include paths must be finite regular files. O_NONBLOCK
	// prevents a malicious or accidentally substituted FIFO/device from
	// hanging startup, SIGHUP validation, or shutdown indefinitely.
	int fd = ::open(abspath.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd != -1) {
		struct stat info = { };
		int const stat_result = fstat(fd, &info);
		if (stat_result != 0 || !S_ISREG(info.st_mode)) {
			int error_number = stat_result != 0 ? errno : EINVAL;
			::close(fd);
			set_error(abspath, 0,
				std::string("configuration path is not a regular file: ") + strerror(error_number));
			return false;
		}
		File file;
		file.path = abspath;
		file.fd = fd;
		file.line = 0;
		files_.push_back(file);
		files_opened_++;
		return true;
	}
	set_error(abspath, 0, std::string("cannot open configuration file: ") + strerror(errno));
	return false;
}

bool LineReader::getline(std::string *out)
{
	while (1) {
		if (!internal_getline(out)) break;
		std::string_view content = misc::trimmed(*out);
		for (unsigned char c : content) {
			if ((c < 0x20 && c != '\t') || c == 0x7f) {
				set_error(current()->path, current()->line,
					"control character is not allowed in configuration text");
				return false;
			}
		}
		if (content.size() > 7 && content.compare(0, 7, "include") == 0 && isspace(static_cast<unsigned char>(content[7]))) {
			std::string source_file = current()->path;
			int source_line = current()->line;
			content.remove_prefix(7);
			content = misc::trimmed(content);

			// Strip comments outside a quoted include path.
			char quote = 0;
			size_t comment = std::string_view::npos;
			for (size_t i = 0; i < content.size(); i++) {
				char c = content[i];
				if (quote) {
					if (c == quote) quote = 0;
				} else if (c == '\'' || c == '"') {
					quote = c;
				} else if (c == ';' || c == '#') {
					comment = i;
					break;
				}
			}
			if (quote) {
				set_error(source_file, source_line, "unterminated quote in include directive");
				break;
			}
			if (comment != std::string_view::npos) {
				content = content.substr(0, comment);
			}
			content = misc::trimmed(content);
			if (content.empty()) {
				set_error(source_file, source_line, "include directive requires a path");
				break;
			}

			std::string include_path;
			if (content.front() == '\'' || content.front() == '"') {
				char delimiter = content.front();
				size_t closing = content.find(delimiter, 1);
				if (closing == std::string_view::npos) {
					set_error(source_file, source_line, "unterminated quote in include directive");
					break;
				}
				if (!misc::trimmed(content.substr(closing + 1)).empty()) {
					set_error(source_file, source_line, "unexpected text after include path");
					break;
				}
				include_path = std::string(content.substr(1, closing - 1));
			} else {
				include_path = std::string(content);
			}
			if (include_path.empty()) {
				set_error(source_file, source_line, "include directive requires a path");
				break;
			}

			std::string path;
			if (include_path.front() == '/') {
				path = include_path;
			} else {
				std::string dir = source_file;
				size_t slash = dir.rfind('/');
				if (slash != std::string::npos) {
					dir.resize(slash + 1);
				} else {
					dir.clear();
				}
				path = dir + include_path;
			}
			if (!open(path)) {
				std::string detail = error_message_;
				set_error(source_file, source_line,
					"failed to include '" + include_path + "': " + detail);
				break;
			}
			continue;
		} else {
			return true;
		}
	}
	return false;
}
