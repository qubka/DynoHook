#include <catch2/catch_test_macros.hpp>

#include "dynohook/os.h"
#include "dynohook/mem_protector.h"
#include "dynohook/mem_accessor.h"

TEST_CASE("Test protflag translation", "[MemProtector],[Enums]") {
	SECTION("flags to native") {
		REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::X) == PAGE_EXECUTE);
		REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::R) == PAGE_READONLY);
		REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::W) == PAGE_READWRITE);
		REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::R | dyno::ProtFlag::W) == PAGE_READWRITE);
		REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::X | dyno::ProtFlag::R) == PAGE_EXECUTE_READ);
		REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::X | dyno::ProtFlag::W) == PAGE_EXECUTE_READWRITE);
		REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::X | dyno::ProtFlag::W | dyno::ProtFlag::R) == PAGE_EXECUTE_READWRITE);
		REQUIRE(dyno::TranslateProtection(dyno::ProtFlag::N) == PAGE_NOACCESS);
	}

	SECTION("native to flags") {
		REQUIRE(dyno::TranslateProtection(PAGE_EXECUTE) == dyno::ProtFlag::X);
		REQUIRE(dyno::TranslateProtection(PAGE_READONLY) == dyno::ProtFlag::R);
		REQUIRE(dyno::TranslateProtection(PAGE_READWRITE) == (dyno::ProtFlag::W | dyno::ProtFlag::R));
		REQUIRE(dyno::TranslateProtection(PAGE_EXECUTE_READ) == (dyno::ProtFlag::X | dyno::ProtFlag::R));
		REQUIRE(dyno::TranslateProtection(PAGE_EXECUTE_READWRITE) == (dyno::ProtFlag::X | dyno::ProtFlag::W | dyno::ProtFlag::R));
		REQUIRE(dyno::TranslateProtection(PAGE_NOACCESS) == dyno::ProtFlag::N);
	}
}

TEST_CASE("Test setting page protections", "[MemProtector]") {
	char* page = (char*)VirtualAlloc(0, 4 * 1024, MEM_COMMIT, PAGE_NOACCESS);
	bool isGood = page != nullptr; // indirection because catch reads var, causing access violation
	REQUIRE(isGood);
	dyno::MemAccessor accessor;

	{
		dyno::MemProtector prot{(uintptr_t)page, 4 * 1024, dyno::ProtFlag::R, accessor};
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == dyno::ProtFlag::N);

		dyno::MemProtector prot1{(uintptr_t)page, 4 * 1024, dyno::ProtFlag::W, accessor};
		REQUIRE(prot1.isGood());
		REQUIRE(prot1.originalProt() == dyno::ProtFlag::R);

		dyno::MemProtector prot2{(uintptr_t)page, 4 * 1024, dyno::ProtFlag::X, accessor};
		REQUIRE(prot2.isGood());
		REQUIRE((prot2.originalProt() & dyno::ProtFlag::W));
	}

	// protection should now be NOACCESS if destructors worked
	{
		dyno::MemProtector prot{(uintptr_t)page, 4 * 1024, dyno::ProtFlag::X | dyno::ProtFlag::R, accessor};
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == dyno::ProtFlag::N);

		dyno::MemProtector prot1{(uintptr_t)page, 4 * 1024, dyno::ProtFlag::X | dyno::ProtFlag::W, accessor};
		REQUIRE(prot.isGood());
		REQUIRE((prot1.originalProt() == (dyno::ProtFlag::X | dyno::ProtFlag::R)));

		dyno::MemProtector prot2{(uintptr_t)page, 4 * 1024, dyno::ProtFlag::X | dyno::ProtFlag::R | dyno::ProtFlag::W, accessor};
		REQUIRE(prot.isGood());
		REQUIRE(prot2.originalProt() == (dyno::ProtFlag::X | dyno::ProtFlag::R | dyno::ProtFlag::W));
	}
	VirtualFree(page, 0, MEM_RELEASE);
}