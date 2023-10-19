#include <catch2/catch_test_macros.hpp>

#include "dynohook/detours/x64_detour.h"
#include "dynohook/conventions/x64/x64MsFastcall.h"
#include "dynohook/tests/stack_canary.h"
#include "dynohook/tests/effect_tracker.h"
#include "dynohook/os.h"

DYNO_NOINLINE void hookMe1() {
    dyno::StackCanary canary;
    volatile int var = 1;
    volatile int var2 = 0;
    var2 += 3;
    var2 = var + var2;
    var2 *= 30 / 3;
    var = 2;
	std::cout << var << " " << var2 << std::endl;
    REQUIRE(var == 2);
    REQUIRE(var2 == 40);
}

DYNO_NOINLINE void hookMe2() {
    dyno::StackCanary canary;
    for (int i = 0; i < 10; i++) {
        std::cout << i << "\n";
    }
    std::cout << std::endl;
}

uint8_t hookMe3[] = {
    0x57, // push rdi
    0x74, 0xf9,
    0x74, 0xf0,//je 0x0
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0xc3
};

uint8_t hookMe4[] = {
    0x57, // push rdi
    0x48, 0x83, 0xec, 0x30, //sub rsp, 0x30
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0x74, 0xf2, //je 0x0
    0xc3
};

// test call instructions in prologue
uint8_t hookMe5[] = {
    0x48, 0x83, 0xEC, 0x28, // 180009240: sub rsp, 28h
    0xE8, 0x96, 0xA8, 0xFF, 0xFF, // call 180003ADF
    0x48, 0x83, 0xC4, 0x28,  // add rsp, 28h
    0x48, 0xFF, 0xA0, 0x20, 0x01, 0x00, 0x00 // jmp qword ptr[rax+120h]
};

// old NtQueueApcThread, call fs:0xC0 was weird
uint8_t hookMe6[] = {
    0xb8, 0x44, 0x00, 0x00, 0x00, // mov eax, 0x44
    0x64, 0xff, 0x15, 0xc0, 0x00, 0x00, 0x00, // call large dword ptr fs:0xc0
    0xc2, 0x14, 0x00 // retn 0x14
};

dyno::EffectTracker effects;

TEST_CASE("Testing x64 detours", "[x64Detour][Detour]") {
	dyno::ConvFunc callConvVoid = []{ return new dyno::x64MsFastcall({}, dyno::DataType::Void); };
	
    SECTION("Normal function") {
		auto PostHook1 = +[](dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			std::cout << "Post Hook 1 Called!" << std::endl;
			effects.peak().trigger();
			return dyno::ReturnAction::Handled;
		};
		
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) &hookMe1, callConvVoid};
        REQUIRE(detour.hook() == true);
		
        detour.addCallback(dyno::CallbackType::Post, PostHook1);
		
        effects.push();
        hookMe1();
        REQUIRE(effects.pop().didExecute(1));
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Normal function rehook") {
		auto PreHook1 = +[](dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			std::cout << "Pre Hook 1 Called!" << std::endl;
			effects.peak().trigger();
			return dyno::ReturnAction::Handled;
		};
		
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) &hookMe1, callConvVoid};
        REQUIRE(detour.hook() == true);

		detour.addCallback(dyno::CallbackType::Pre, PreHook1);

        effects.push();
        REQUIRE(detour.rehook() == true); // can only really test this doesn't cause memory corruption easily
        hookMe1();
        REQUIRE(effects.pop().didExecute(1));
        REQUIRE(detour.unhook() == true);
    }

        // In release mode win apis usually go through two levels of jmps
        /*
        0xe9 ... jmp iat_thunk

        iat_thunk:
        0xff 25 ... jmp [api_implementation]

        api_implementation:
            sub rsp, ...
            ... the goods ...
        */
    SECTION("WinApi Indirection") {
		dyno::ConvFunc callConvWinApi = []{ return new dyno::x64MsFastcall({dyno::DataType::Pointer, dyno::DataType::Pointer, dyno::DataType::Int32, dyno::DataType::Int32}, dyno::DataType::Pointer); };
		
		auto PostCreateMutexExA = +[](dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
            LPCSTR lpName = hook.getArgument<LPCSTR>(1);
			std::cout << "kernel32!CreateMutexExA - Name: " << lpName << std::endl;
			return dyno::ReturnAction::Ignored;
		};
		
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) &CreateMutexExA, callConvWinApi};
		
        detour.addCallback(dyno::CallbackType::Post, PostCreateMutexExA);
		
        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Loop function") {
		auto PostHook2 = +[](dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			std::cout << "Post Hook 2 Called!" << std::endl;
			effects.peak().trigger();
			return dyno::ReturnAction::Handled;
		};
		
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) &hookMe2, callConvVoid};
        REQUIRE(detour.hook() == true);
	
		detour.addCallback(dyno::CallbackType::Post, PostHook2);

        effects.push();
        hookMe2();
        REQUIRE(effects.pop().didExecute(1));
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Jmp into prol w/src in range") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) &hookMe3, callConvVoid};

        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Jmp into prol w/src out of range") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) &hookMe4, callConvVoid};

        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Call instruction early in prologue") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) &hookMe5, callConvVoid};

        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Call with fs base") {
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t)&hookMe6, callConvVoid};

        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unhook() == true);
    }

    /*SECTION("hook malloc") {
		dyno::ConvFunc callConvWinApi = []{ return new dyno::x64MsFastcall({dyno::DataType::UInt64}, dyno::DataType::Pointer); };
		
		auto PreMalloc = +[](dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
            size_t size = hook.getArgument<size_t>(0);
			std::cout << "malloc - size: " << size << std::endl;
			return dyno::ReturnAction::Ignored;
		};
		
        dyno::StackCanary canary;
        dyno::x64Detour detour{(uintptr_t) &malloc, callConvWinApi};
        effects.push(); // catch does some allocations, push effect first so peak works

        REQUIRE(detour.hook());
		
		detour.addCallback(dyno::CallbackType::Pre, PreMalloc);

        void* pMem = malloc(16);
        free(pMem);
        detour.unhook(); // unhook so we can pop safely w/o catch allocation happening again
        REQUIRE(effects.pop().didExecute(1));
    }

    SECTION("queue apc thread") {
		dyno::ConvFunc callConvWinApi = []{ return new dyno::x64MsFastcall({dyno::DataType::Pointer, dyno::DataType::Pointer, dyno::DataType::Pointer, dyno::DataType::Pointer, dyno::DataType::UInt32}, dyno::DataType::UInt32); };

        typedef void(*PKNORMAL_ROUTINE)(void* NormalContext, void* SystemArgument1, void* SystemArgument2);
        typedef unsigned long(__stdcall* tNtQueueApcThread)(void* ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, void* NormalContext, void* SystemArgument1, void* SystemArgument2);
        tNtQueueApcThread pNtQueueApcthread = (tNtQueueApcThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");

		auto PostNtQueueApcthread = +[](dyno::CallbackType type, dyno::Hook& hook) {
			std::cout << "hkNtQueueApcThread!" << std::endl;
			return dyno::ReturnAction::Ignored;
		};
		
        dyno::x64Detour detour{(uintptr_t)pNtQueueApcthread, callConvWinApi};
        effects.push(); // catch does some allocations, push effect first so peak works
        REQUIRE(detour.hook() == true);
		
		detour.addCallback(dyno::CallbackType::Post, PostNtQueueApcthread);
    }*/
}