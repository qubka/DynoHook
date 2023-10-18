using namespace dyno;

void Log::registerLogger(std::shared_ptr<Logger> logger) {
	m_logger = logger;
}

void Log::log(const std::string& msg, ErrorLevel level) {
	if (m_logger)
		m_logger->log(msg, level);
}

void ErrorLogger::log(const std::string& msg, ErrorLevel level) {
	push({ msg, level });
}

void ErrorLogger::push(const Error& err) {
	if (err.lvl >= m_level) {
		switch (err.lvl) {
		case ErrorLevel::INFO:
			std::cout << "[+] Info: " << err.msg << std::endl;
			break;
		case ErrorLevel::WARN:
			std::cout << "[!] Warn: " << err.msg << std::endl;
			break;
		case ErrorLevel::SEV:
			std::cout << "[!] Error: " << err.msg << std::endl;
			break;
		default:
			std::cout << "Unsupported error message logged " << err.msg << std::endl;
		}
	}

	m_log.push_back(err);
}

Error ErrorLogger::pop() {
	Error err{};
	if (!m_log.empty()) {
		err = m_log.back();
		m_log.pop_back();
	}
	return err;
}

ErrorLogger& ErrorLogger::Get() {
	static ErrorLogger logger;
	return logger;
}