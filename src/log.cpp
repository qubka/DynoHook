#include <dynohook/log.h>

#include <iostream>

using namespace dyno;

void Log::registerLogger(std::shared_ptr<Logger> logger) {
	m_logger = std::move(logger);
}

void Log::log(const std::string& msg, ErrorLevel level) {
	if (m_logger)
		m_logger->log(msg, level);
}

void ErrorLogger::log(const std::string& msg, ErrorLevel level) {
	push(msg, level);
}

void ErrorLogger::push(const std::string& msg, ErrorLevel level) {
	if (level >= m_level) {
		switch (level) {
		case ErrorLevel::INFO:
			std::cout << "[+] Info: " << msg << std::endl;
			break;
		case ErrorLevel::WARN:
			std::cout << "[!] Warn: " << msg << std::endl;
			break;
		case ErrorLevel::ERR:
			std::cout << "[!] Error: " << msg << std::endl;
			break;
		default:
			std::cout << "Unsupported error message logged " << msg << std::endl;
		}
	}

	m_log.push_back(msg);
}

std::string ErrorLogger::pop() {
	std::string msg;
	if (!m_log.empty()) {
		msg = std::move(m_log.back());
		m_log.pop_back();
	}
	return msg;
}


void ErrorLogger::setLogLevel(ErrorLevel level) {
	m_level = level;
}

ErrorLogger& ErrorLogger::Get() {
	static ErrorLogger logger;
	return logger;
}