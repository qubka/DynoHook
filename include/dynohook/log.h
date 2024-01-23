#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <vector>

namespace dyno {
	enum class ErrorLevel : uint8_t {
		NONE,
		INFO,
		WARN,
		SEV,
	};

	class Logger {
	public:
		Logger() = default;
		virtual ~Logger() = default;
	
		virtual void log(const std::string& msg, ErrorLevel level) = 0;
	};

	class Log {
	public:
		static void registerLogger(std::shared_ptr<Logger> logger);
		static void log(const std::string& msg, ErrorLevel level);
		
	private:
		static inline std::shared_ptr<Logger> m_logger = nullptr;
	};

	class ErrorLogger : public Logger {
	public:
		ErrorLogger() = default;
		~ErrorLogger() override = default;
	
		void log(const std::string& msg, ErrorLevel level) override;

		void push(const std::string& msg, ErrorLevel level);
		std::string pop();
		
		static ErrorLogger& Get();
		
		void setLogLevel(ErrorLevel level);

	private:
		std::vector<std::string> m_log;
		ErrorLevel m_level = ErrorLevel::INFO;
	};
}

#if DYNO_LOGGING
#define DYNO_LOG(msg, lvl) dyno::Log::log(msg, lvl)
#else
#define DYNO_LOG(msg, lvl)
#endif
