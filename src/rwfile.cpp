
#include "rwfile.h"
#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef WIN32
#pragma warning(disable : 4996)
#endif

bool readfile(char const *path, std::vector<char> *out, int maxsize)
{
	out->clear();
	bool ok = false;
#ifdef WIN32
	int fd = open(path, O_RDONLY | O_BINARY | O_CLOEXEC);
#else
	int fd = open(path, O_RDONLY | O_CLOEXEC);
#endif
	if (fd != -1) {
		struct stat st;
		if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
			decltype(st.st_size) size = st.st_size;
			if (size == 0 && maxsize > 0) {
				size = maxsize;
			}
			if (maxsize < 0 || size <= maxsize) {
				ok = true;
				out->resize(size);
				int pos = 0;
				while (pos < size) {
					int n = size - pos;
					if (n > 65536) {
						n = 65536;
					}
					ssize_t r = read(fd, &out->at(pos), n);
					if (r < 0 && errno == EINTR) continue;
					if (r == 0) {
						if (st.st_size == 0) {
							out->resize(pos);
							break;
						}
					}
					if (r != n) {
						if (st.st_size > 0) {
							out->clear();
							ok = false;
							break;
						}
					}
					pos += r;
				}
			}
		}
		close(fd);
	}
	return ok;
}

bool writefile(char const *path, std::vector<char> const *vec)
{
	bool ok = false;
#ifdef WIN32
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | O_CLOEXEC, S_IREAD | S_IWRITE);
#else
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
#endif
	if (fd != -1) {
		ok = true;
		int pos = 0;
		while (pos < (int)vec->size()) {
			int n = (int)vec->size() - pos;
			if (n > 65536) {
				n = 65536;
			}
			ssize_t w = write(fd, &vec->at(pos), n);
			if (w < 0 && errno == EINTR) continue;
			if (w != n) {
				ok = false;
				break;
			}
			pos += n;
		}
		close(fd);
	}
	return ok;
}
