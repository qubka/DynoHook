#include <catch2/catch_session.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <catch2/internal/catch_leak_detector.hpp>

namespace Catch {
    CATCH_INTERNAL_START_WARNINGS_SUPPRESSION
    CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS
    static LeakDetector leakDetector;
    CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION
}

int main(int argc, char* argv[]) {
    // We want to force the linker not to discard the global variable
    // and its constructor, as it (optionally) registers leak detector
    (void)&Catch::leakDetector;

    auto logger = std::make_shared<dyno::ErrorLogger>();
    logger->setLogLevel(dyno::ErrorLevel::INFO);
    dyno::Log::registerLogger(logger);

    DYNO_LOG("Git: [" DYNO_GIT_COMMIT_HASH "]:(" DYNO_GIT_TAG ") - " DYNO_GIT_COMMIT_SUBJECT " on " DYNO_GIT_BRANCH " at '" DYNO_GIT_COMMIT_DATE "'", dyno::ErrorLevel::INFO);
    DYNO_LOG("Compiled on: " DYNO_COMPILED_SYSTEM " from: " DYNO_COMPILED_GENERATOR" with: '" DYNO_COMPILED_COMPILER "'", dyno::ErrorLevel::INFO);

    return Catch::Session().run(argc, argv);
}
