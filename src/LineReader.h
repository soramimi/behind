#ifndef LINEREADER_H
#define LINEREADER_H

#include <string>
#include <vector>

class LineReader {
private:
	struct File {
		std::string path;
		int fd = -1;
		char buffer[1024];
		size_t offset = 0;
		size_t length = 0;
		char last_char = 0;
		bool eof = false;
		int line = 0;
	};
	std::vector<File> files_;
	std::string error_file_;
	std::string error_message_;
	int error_line_ = 0;
	size_t bytes_read_ = 0;
	size_t files_opened_ = 0;
	File *current();
	void close_all();
	void close_one();
	void set_error(std::string file, int line, std::string message);
	bool internal_getline(std::string *out);
public:
	LineReader();
	~LineReader();
	std::string file() const;
	int line() const;
	bool failed() const;
	std::string const &error_file() const;
	int error_line() const;
	std::string const &error_message() const;
	bool open(std::string const &path);
	bool getline(std::string *out);
};

#endif // LINEREADER_H
