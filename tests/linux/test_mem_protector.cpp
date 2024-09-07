#include <catch2/catch_test_macros.hpp>

#include "dynohook/os.h"
#include "dynohook/mem_protector.h"
#include "dynohook/mem_accessor.h"

TEST_CASE("Test protflag translation", "[MemProtector],[Enums]") {
    SECTION("flags to native") {
        REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::X) == PROT_EXEC);
        REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::R) == PROT_READ);
        REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::W) == PROT_WRITE);
        REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::R | dyno::ProtFlag::W) == (PROT_READ|PROT_WRITE));
        REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::X | dyno::ProtFlag::R) == (PROT_EXEC|PROT_READ));
        REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::X | dyno::ProtFlag::W) == (PROT_EXEC|PROT_WRITE));
        REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::X | dyno::ProtFlag::W | dyno::ProtFlag::R) == (PROT_EXEC|PROT_WRITE|PROT_READ));
        REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::N) == PROT_NONE);
    }

    SECTION("native to flags") {
        REQUIRE(dyno::TranslateProtection(PROT_EXEC) == dyno::ProtFlag::X);
        REQUIRE(dyno::TranslateProtection(PROT_READ) == dyno::ProtFlag::R);
        REQUIRE(dyno::TranslateProtection(PROT_WRITE) == dyno::ProtFlag::W);
        REQUIRE(dyno::TranslateProtection(PROT_WRITE|PROT_READ) == (dyno::ProtFlag::W | dyno::ProtFlag::R));
        REQUIRE(dyno::TranslateProtection(PROT_EXEC|PROT_READ) == (dyno::ProtFlag::X | dyno::ProtFlag::R));
        REQUIRE(dyno::TranslateProtection(PROT_EXEC|PROT_WRITE) == (dyno::ProtFlag::X | dyno::ProtFlag::W));
        REQUIRE(dyno::TranslateProtection(PROT_EXEC|PROT_WRITE|PROT_READ) == (dyno::ProtFlag::X | dyno::ProtFlag::W | dyno::ProtFlag::R));
        REQUIRE(dyno::TranslateProtection(PROT_NONE) == dyno::ProtFlag::N);
    }
}

TEST_CASE("Test setting page protections", "[MemProtector]") {
    char* page = (char*)mmap(nullptr, 4*1024, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bool isGood = page != nullptr; // indirection because catch reads var, causing access violation
    REQUIRE(isGood);
    dyno::MemAccessor accessor;

    {
        dyno::MemProtector prot((uintptr_t)page, 4 * 1024, dyno::ProtFlag::R, accessor);
        REQUIRE(prot.isGood());
        REQUIRE(prot.originalProt() == dyno::ProtFlag::N);

        dyno::MemProtector prot1((uintptr_t)page, 4 * 1024, dyno::ProtFlag::W, accessor);
        REQUIRE(prot1.isGood());
        REQUIRE(prot1.originalProt() == dyno::ProtFlag::R);

        dyno::MemProtector prot2((uintptr_t)page, 4 * 1024, dyno::ProtFlag::X, accessor);
        REQUIRE(prot2.isGood());
        REQUIRE((prot2.originalProt() & dyno::ProtFlag::W));
    }

    // protection should now be NOACCESS if destructors worked
    {
        dyno::MemProtector prot((uintptr_t)page, 4 * 1024, dyno::ProtFlag::X | dyno::ProtFlag::R, accessor);
        REQUIRE(prot.isGood());
        REQUIRE(prot.originalProt() == dyno::ProtFlag::N);

        dyno::MemProtector prot1((uintptr_t)page, 4 * 1024, dyno::ProtFlag::X | dyno::ProtFlag::W, accessor);
        REQUIRE(prot.isGood());
        REQUIRE((prot1.originalProt() == (dyno::ProtFlag::X | dyno::ProtFlag::R)));

        dyno::MemProtector prot2((uintptr_t)page, 4 * 1024, dyno::ProtFlag::X | dyno::ProtFlag::R | dyno::ProtFlag::W, accessor);
        REQUIRE(prot.isGood());
        REQUIRE(prot2.originalProt() == (dyno::ProtFlag::X | dyno::ProtFlag::W));
    }
    munmap(page, 4*1024);
}