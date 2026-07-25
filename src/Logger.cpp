
#include "Logger.h"
#include <cctype>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

Logger x_logger;

// Set to true to include the source file and line in every log line. Kept as a
// single flag so that x_logprint() does not pay for capturing the file name
// (a std::string allocation per log line) while it is disabled.
static constexpr bool FILELINE = false;

struct Logger::LogItem {
	Logger::time_point_t tp = { };
	int level = 0;
	std::string message;
	std::string file;
	int line = 0;
};

struct Logger::Private {
	std::string log_file;
	bool paused = false;
	int fd_log = -1;
	std::vector<Logger::LogItem> items;
	size_t dropped = 0;
	std::thread thread;
	std::mutex mutex;
	// Guards fd_log and the log file itself. Separate from `mutex` so that file
	// I/O in the writer thread never blocks producers on the query hot path.
	// Without it, x_open() on SIGHUP reload could close fd_log while the writer
	// held that number in a register; the fd is then handed to a new listening
	// socket and log text gets written into a DNS socket.
	std::mutex file_mutex;
	std::condition_variable cv;
	bool interrupted = false;
};

Logger::Logger()
	: m(new Private)
{
}

Logger::~Logger()
{
	x_stop();
	delete m;
}

Logger::time_point_t Logger::now()
{
	return std::chrono::system_clock::now();
}

void Logger::write(char const *ptr, size_t len)
{
	if (m->fd_log != -1) {
		::write(m->fd_log, ptr, len);
	} else {
		::write(fileno(stderr), ptr, len);
	}
}

void Logger::write(LogItem const &item)
{
	if (item.level == LOG_RAW) {
		write(item.message.c_str(), item.message.size());
	} else {
		auto dur = item.tp.time_since_epoch();
		auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
		time_t t = msec / 1000;
		struct tm tm_buf;
		struct tm *tm = localtime_r(&t, &tm_buf);
		char *text = nullptr;
		std::string msg = item.message;
		if (FILELINE) {
			char buf[100];
			sprintf(buf, "(%d)", item.line);
			msg += " @@";
			msg += item.file;
			msg += buf;
		}
		int len = asprintf(&text, "[%d-%02d-%02d,%02d:%02d:%02d.%03d] %s\n", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, int(msec % 1000), msg.c_str());
		if (text) {
			if (item.level & LOG_DEFAULT) {
				write(text, len);
			}
			if (item.level & LOG_STDERR) {
				fwrite(text, 1, len, stderr);
			}
			free(text);
		}
	}
}

void Logger::rotate()
{
	if (m->fd_log == -1) return;

	const int N = 9;
	int i = N;
	std::string dst = m->log_file + '.' + std::to_string(i);
	unlink(dst.c_str());
	while (i > 0) {
		i--;
		std::string src = m->log_file + '.' + std::to_string(i);
		rename(src.c_str(), dst.c_str());
		dst = src;
	}

	int fd_dst = ::open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC, log_file_permission());
	if (fd_dst != -1) {
		lseek(m->fd_log, 0, SEEK_SET);
		while (1) {
			char buf[4096];
			int n = read(m->fd_log, buf, sizeof(buf));
			if (n < 1) break;
			if (::write(fd_dst, buf, n) != n) break;
		}
		::close(fd_dst);
	}
	lseek(m->fd_log, 0, SEEK_SET);
	ftruncate(m->fd_log, 0);
}

void Logger::x_open(std::string const &log_file)
{
	std::lock_guard lock(m->file_mutex);
	if (m->fd_log != -1) {
		close(m->fd_log);
		m->fd_log = -1;
	}
	m->log_file = log_file;
	m->fd_log = ::open(m->log_file.c_str(), O_RDWR | O_CREAT | O_APPEND, log_file_permission());
	if (m->fd_log == -1) {
		fprintf(stderr, "failed to open log file: %s\n", m->log_file.c_str());
	}
}

void Logger::x_close()
{
	std::lock_guard lock(m->file_mutex);
	if (m->fd_log != -1) {
		close(m->fd_log);
		m->fd_log = -1;
	}
}

void Logger::x_start()
{
	{
		std::lock_guard lock(m->mutex);
		m->paused = false;
		m->interrupted = false;
		m->dropped = 0;
	}

	m->thread = std::thread([this]() {
		while (1) {
			std::vector<LogItem> items;
			size_t dropped = 0;
			{
				std::unique_lock lock(m->mutex);
				// `paused` is a wait condition, not a reason to loop: the old
				// `if (m->paused) continue;` re-acquired the mutex as fast as it
				// could whenever the queue was non-empty while paused, pinning a
				// core. Keep flushing once interrupted so shutdown loses nothing.
				while (!m->interrupted && (m->paused || m->items.empty())) {
					m->cv.wait(lock);
				}
				if (m->items.empty()) return; // interrupted and drained
				std::swap(items, m->items);
				dropped = m->dropped;
				m->dropped = 0;
			}
			std::lock_guard file_lock(m->file_mutex);
			{
				struct stat st;
				if (m->fd_log != -1 && fstat(m->fd_log, &st) == 0 && st.st_size >= log_rotate_size()) {
					rotate();
				}
			}
			for (LogItem const &item : items) {
				write(item);
			}
			if (dropped > 0) {
				char text[128];
				int len = snprintf(text, sizeof(text), "(warning) %zu log lines dropped: the log queue was full\n", dropped);
				if (len > 0) write(text, (size_t)len);
			}
		}
	});
}

void Logger::x_stop()
{
	{
		std::lock_guard lock(m->mutex);
		m->paused = false;
		m->interrupted = true;
	}
	m->cv.notify_all();
	if (m->thread.joinable()) {
		m->thread.join();
	}
	x_close();
	std::lock_guard lock(m->mutex);
	m->interrupted = false;
}

void Logger::x_pause(bool f)
{
	std::lock_guard lock(m->mutex);
	m->paused = f;
	if (!f) {
		m->cv.notify_all();
	}
}

void Logger::start()
{
	x_logger.x_start();
}

void Logger::stop()
{
	x_logger.x_stop();
}

void Logger::open(const std::string &log_file)
{
	x_logger.x_open(log_file);
}

void Logger::push(Logger::LogItem &&item)
{
	bool notify = false;
	{
		std::lock_guard lock(m->mutex);
		if (m->items.size() >= MAX_QUEUED_ITEMS) {
			m->dropped++;
			return;
		}
		m->items.push_back(std::move(item));
		// Only the empty -> non-empty transition needs a wakeup; the writer swaps
		// the whole queue in one go. Notifying per line cost a futex syscall per
		// log line on the query hot path.
		notify = m->items.size() == 1 && !m->paused;
	}
	if (notify) {
		m->cv.notify_one();
	}
}

void Logger::x_logprint(const char *file, int line, int level, std::string_view str)
{
	LogItem item;
	item.tp = now();
	item.level = level;
	item.line = line;
	if (FILELINE) {
		item.file = file;
	}
	if (level != LOG_RAW) {
		while (!str.empty() && isspace((unsigned char)str.back())) {
			str.remove_suffix(1);
		}
	}
	item.message = std::string(str);
	push(std::move(item));
}

void Logger::x_logprintf(char const *file, int line, int level, char const *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char *msg = nullptr;
	int len = vasprintf(&msg, fmt, ap);
	if (msg) {
		std::string_view v(msg, len);
		x_logprint(file, line, level, v);
		free(msg);
	}
	va_end(ap);
}

void Logger::pause(bool f)
{
	x_logger.x_pause(f);
}
