#include <catch2/catch_test_macros.hpp>

#include "dynohook/detours/x64_detour.h"
#include "dynohook/conventions/x64/x64MsFastcall.h"
#include "dynohook/tests/stack_canary.h"
#include "dynohook/os.h"

#include <memoryapi.h>

uint8_t cmpQwordImm[] = {
    0x48, 0x81, 0x3D, 0xF5, 0xFF, 0xFF, 0xFF, 0x78, 0x56, 0x34, 0x12, // cmp qword ptr ds:[rip - 11], 0x12345678
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,                         // mov rax, 0x1337
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                 // nop x8
    0xC3                                                              // ret
};

uint8_t cmpDwordImm[] = {
    0x81, 0x05, 0xF6, 0xFF, 0xFF, 0xFF, 0x78, 0x56, 0x34, 0x12, // add dword ptr ds:[rip - 10], 0x12345678
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,                   // mov rax, 0x1337
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                 // nop x8
    0xC3                                                        // ret
};

uint8_t cmpWordImm[] = {
    0x66, 0x81, 0x3D, 0xF7, 0xFF, 0xFF, 0xFF, 0x34, 0x12, // cmp word ptr ds:[rip - 9], 0x1234
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,             // mov rax, 0x1337
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                 // nop x8
    0xC3                                                  // ret
};

uint8_t cmpByteImm[] = {
    0x80, 0x3D, 0xF9, 0xFF, 0xFF, 0xFF, 0x12, // cmp byte ptr ds:[rip - 7], 0x12
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, // mov rax, 0x1337
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                 // nop x8
    0xC3                                      // ret
};

uint8_t cmpQwordRegR10[] = {
    0x4C, 0x39, 0x15, 0xF9, 0xFF, 0xFF, 0xFF, // cmp qword ptr ds:[rip - 7], r10
    0xB8, 0x37, 0x13, 0x00, 0x00,             // mov eax, 0x1337
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                 // nop x8
    0xC3                                      // ret
};

uint8_t cmpRegADword[] = {
    0x3B, 0x05, 0xFA, 0xFF, 0xFF, 0xFF, // cmp eax, dword ptr ds:[rip - 6]
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                 // nop x8
    0xC3                                // ret
};

uint8_t cmpWordRegB[] = {
    0x66, 0x39, 0x1D, 0xF9, 0xFF, 0xFF, 0xFF, // cmp word ptr ds:[rip - 7], bx
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                 // nop x8
    0xC3                                      // ret
};

uint8_t cmpR15bByte[] = {
    0x44, 0x3A, 0x3D, 0xF9, 0xFF, 0xFF, 0xFF, // cmp r15b, byte ptr ds:[rip - 7]
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                 // nop x8
    0xC3                                      // ret
};

// TODO: Translation + INPLACE scheme

TEST_CASE("Testing Detours with Translations", "[Translation][x64Detour]") {
    dyno::EffectTracker ripEffects;
	
	// Immediate
	typedef int (* IntFn)();

	dyno::ReturnAction PreCallback(dyno::CallbackType hookType, dyno::Hook& hook) {x
		dyno::StackCanary canary;
		ripEffects.peak().trigger();
		std::cout << "PrePreCallback: %s\n" << __func__ << std::endl;
		return dyno::ReturnAction::Handled;
	}

	dyno::ReturnAction PostCallback(dyno::CallbackType hookType, dyno::Hook& hook) {
		dyno::StackCanary canary;
		ripEffects.peak().trigger();
		std::cout << "PostCallback: %s\n" << __func__ << std::endl;
		
		int return_value = hook.getReturnValue<int>();
		assert(return_value == 0x1337);

		return dyno::ReturnAction::Ignored;
	}
	
	dyno::ConvFunc CallConvRetInt = []{ return new dyno::x64MsFastcall({}, dyno::DataType::Int); };
	dyno::ConvFunc CallConvRetVoid = []{ return new dyno::x64MsFastcall({}, dyno::DataType::Void); };

    SECTION("cmp qword & imm") {
        dyno::StackCanary canary;

        DWORD flOldProtect;
        VirtualProtect((void*) cmpQwordImm, (SIZE_T) sizeof(cmpQwordImm), PAGE_EXECUTE_READWRITE, &flOldProtect);

        dyno::x64Detour detour{(uintptr_t) cmpQwordImm, CallConvRetInt};

        REQUIRE(detour.hook());

		detour.addCallback(dyno::CallbackType::Pre, (dyno::CallbackHandler*) &PreCallback);
		detour.addCallback(dyno::CallbackType::Post, (dyno::CallbackHandler*) &PostCallback);

        ripEffects.push();

        IntFn fn = (IntFn) cmpQwordImm;
		int result = fn();

        REQUIRE(ripEffects.pop().didExecute(2));
        REQUIRE(result == 0x1337);

        REQUIRE(detour.unhook());
    }

    SECTION("cmp dword & imm") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) cmpDwordImm, CallConvRetInt};

        REQUIRE(detour.hook());
        REQUIRE(detour.unhook());
    }


    SECTION("cmp word & imm") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) cmpWordImm, CallConvRetInt};

        REQUIRE(detour.hook());
        REQUIRE(detour.unhook());
    }

    SECTION("cmp byte & imm") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) cmpByteImm, CallConvRetInt};

        REQUIRE(detour.hook());
        REQUIRE(detour.unhook());
    }

    // Registers

    SECTION("cmp qword & reg") {
        dyno::StackCanary canary;

        DWORD flOldProtect;
        VirtualProtect((void*) cmpQwordRegR10, (SIZE_T) sizeof(cmpQwordRegR10), PAGE_EXECUTE_READWRITE, &flOldProtect);

        dyno::x64Detour detour{(uintptr_t) cmpQwordRegR10, CallConvRetInt};

        REQUIRE(detour.hook());

		detour.addCallback(dyno::CallbackType::Pre, (dyno::CallbackHandler*) &PreCallback);
		detour.addCallback(dyno::CallbackType::Post, (dyno::CallbackHandler*) &PostCallback);

        ripEffects.push();

        IntFn fn = (IntFn) cmpQwordRegR10;
		int result = fn();
		
        REQUIRE(ripEffects.pop().didExecute(2));
        REQUIRE(result == 0x1337);

        REQUIRE(detour.unhook());
    }

    // Subsequent hooks don't test trampoline calls

    SECTION("cmp dword & reg") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) cmpRegADword, CallConvRetVoid};

        REQUIRE(detour.hook());
        REQUIRE(detour.unhook());
    }

    SECTION("cmp word & reg") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) cmpWordRegB, CallConvRetVoid};

        REQUIRE(detour.hook());
        REQUIRE(detour.unhook());
    }

    SECTION("cmp byte & reg") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) cmpR15bByte, CallConvRetVoid};

        REQUIRE(detour.hook());
        REQUIRE(detour.unhook());
    }
}