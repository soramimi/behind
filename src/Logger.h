#ifndef LOGGER_H
#define LOGGER_H

#include <chrono>

class Logger {
private:
	struct Private;
	Private *m;
	struct LogItem;
	typedef std::chrono::system_clock::time_point time_point_t;
	time_point_t now();
	void write(const char *ptr, size_t len);
	void write(const LogItem &item);
	void push(const LogItem &item);
	void x_start();
	void x_stop();
public:
	Logger();
	~Logger();
	void x_logprintf(const char *file, int line, int level, const char *fmt, ...);
	static void start();
	static void stop();
};

extern Logger x_logger;

#define LOG_RAW 0
#define LOG_DEFAULT 1
#define logprintf(LEVEL, FMT, ...) x_logger.x_logprintf(__FILE__, __LINE__, LEVEL, FMT, ##__VA_ARGS__)

#endif // LOGGER_H
