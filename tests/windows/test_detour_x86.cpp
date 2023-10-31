#include <catch2/catch_test_macros.hpp>

#include "dynohook/detours/x86_detour.h"
#include "dynohook/conventions/x86_ms_cdecl.h"
#include "dynohook/tests/stack_canary.h"
#include "dynohook/tests/effect_tracker.h"
#include "dynohook/os.h"

dyno::EffectTracker effects;

DYNO_NOINLINE int DYNO_CDECL hookMe1() {
    volatile int var = 1;
    volatile int var2 = 0;
    var2 += 3;
    var2 = var + var2;
    var2 *= 30 / 3;
    var = 2;
    printf("%d %d\n", var, var2); // 2, 40
    return var;
}

/*  55                      push   ebp
1:  8b ec                   mov    ebp,esp
3:  74 fb                   je     0x0
5:  74 fa                   je     0x1
7:  8b ec                   mov    ebp,esp
9:  8b ec                   mov    ebp,esp
b:  8b ec                   mov    ebp,esp
d:  90                      nop
e:  90                      nop
f:  90                      nop
10: 90                      nop
11: 90                      nop */
uint8_t hookMe2[] = {0x55, 0x8b, 0xec, 0x74, 0xFB, 0x74, 0xea, 0x74, 0xFA, 0x8b, 0xec, 0x8b, 0xec, 0x8b, 0xec,
                           0x90, 0x90, 0x90, 0x90, 0x90};

/*
0:  55                      push   ebp
1:  89 e5                   mov    ebp,esp
3:  89 e5                   mov    ebp,esp
5:  89 e5                   mov    ebp,esp
7:  89 e5                   mov    ebp,esp
9:  90                      nop
a:  90                      nop
b:  7f f4                   jg     0x1
*/
uint8_t hookMe3[] = {0x55, 0x89, 0xE5, 0x89, 0xE5, 0x89, 0xE5, 0x89, 0xE5, 0x90, 0x90, 0x7F, 0xF4};

uint8_t hookMe4[] = {
    0x55,                   // push ebp
    0x8B, 0xEC,             // mov ebp, esp
    0x56,                   // push esi
    0x8B, 0x75, 0x08,       // mov esi, [ebp+8]
    0xF6, 0x46, 0x30, 0x02, // test byte ptr ds:[esi+0x30], 0x2
    0xC3                    // ret
};

// old NtQueueApcThread, call fs:0xC0 was weird
uint8_t hookMe5[] =
    {
        0xb8, 0x44, 0x00, 0x00, 0x00, // mov eax, 0x44
        0x64, 0xff, 0x15, 0xc0, 0x00, 0x00, 0x00, // call dword ptr fs:0xc0
        0xc2, 0x14, 0x00 // retn 0x14
    };

DYNO_NOINLINE void DYNO_NAKED hookMeLoop() {
#ifdef _MSC_VER
    __asm {
        xor eax, eax
        start :
        inc eax
        cmp eax, 5
        jle start
        ret
    }
#elif __GNUC__
    asm(
        "xor %eax, %eax;\n\t"
        "START: inc %eax;\n\t"
        "cmp $5, %eax;\n\t"
        "jle START;\n\t"
        "ret;"
    );
#else
#error "Please implement this for your compiler!"
#endif
}

TEST_CASE("Testing x86 detours", "[x86Detour][Detour]") {
    dyno::ConvFunc callConvInt = []{ return new dyno::x86MsCdecl({}, dyno::DataType::Int32); };
    dyno::ConvFunc callConvVoid = []{ return new dyno::x86MsCdecl({}, dyno::DataType::Void); };

    auto PostHook1 = +[](dyno::CallbackType type, dyno::Hook& hook) {
        DYNO_UNUSED(type);
        DYNO_UNUSED(hook);
        dyno::StackCanary canary;
        std::cout << "Post Hook 1 Called!" << std::endl;
        effects.peak().trigger();
        return dyno::ReturnAction::Handled;
    };

    SECTION("Normal function") {
        dyno::StackCanary canary;
        dyno::x86Detour detour{(uintptr_t) &hookMe1, callConvInt};
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Post, PostHook1);

        effects.push();
        volatile auto result = hookMe1();
        DYNO_UNUSED(result);
        REQUIRE(effects.pop().didExecute(1));
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Normal function rehook") {
        dyno::StackCanary canary;
        dyno::x86Detour detour{(uintptr_t) &hookMe1, callConvInt};
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Post, PostHook1);

        effects.push();
        REQUIRE(detour.rehook() == true); // can only really test this doesn't cause memory corruption easily
        volatile auto result = hookMe1();
        DYNO_UNUSED(result);
        REQUIRE(effects.pop().didExecute(1));
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Jmp into prologue w/ src in range") {
        dyno::x86Detour detour{(uintptr_t) &hookMe2, callConvVoid};

        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Jmp into prologue w/ src out of range") {
        dyno::x86Detour detour{(uintptr_t) &hookMe3, callConvVoid};
        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Test instruction in prologue") {
        dyno::x86Detour detour{(uintptr_t) &hookMe4, callConvVoid};
        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Call with fs base") {
        dyno::x86Detour detour{(uintptr_t)&hookMe5, callConvVoid};
        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unhook() == true);
    }

    SECTION("Loop") {
        auto PreLoopHook = +[](dyno::CallbackType type, dyno::Hook& hook) {
            DYNO_UNUSED(type);
            DYNO_UNUSED(hook);
            dyno::StackCanary canary;
            std::cout << "Loop Hook Called!" << std::endl;
            effects.peak().trigger();
            return dyno::ReturnAction::Handled;
        };

        dyno::StackCanary canary;
        dyno::x86Detour detour{(uintptr_t) &hookMeLoop, callConvVoid};
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Pre, PreLoopHook);

        effects.push();
        hookMeLoop();
        REQUIRE(effects.pop().didExecute(1));
        REQUIRE(detour.unhook() == true);
    }

    /*SECTION("hook printf") {
        dyno::x86Detour detour{(uintptr_t) &printf, (uintptr_t) h_hookPrintf, &hookPrintfTramp);
        REQUIRE(detour.hook() == true);

        effects.push();
        printf("%s %f\n", "hi", .5f);
        detour.unhook();
        REQUIRE(effects.pop().didExecute());
    }

    // it's a pun...
    SECTION("hook pow") {
        dyno::x86Detour detour{(uintptr_t) pFnPowDouble, (uintptr_t) h_hookPow, &hookPowTramp);
        REQUIRE(detour.hook() == true);

        effects.push();
        volatile double result = pFnPowDouble(2, 2);
        DYNO_UNUSED(result);
        detour.unhook();
        REQUIRE(effects.pop().didExecute());
    }

    SECTION("hook malloc") {
        dyno::x86Detour detour{(uintptr_t) &malloc, (uintptr_t) h_hookMalloc, &hookMallocTramp);
        effects.push(); // catch does some allocations, push effect first so peak works
        REQUIRE(detour.hook() == true);

        void* pMem = malloc(16);
        free(pMem);
        detour.unhook(); // unhook so we can pop safely w/o catch allocation happening again
        REQUIRE(effects.pop().didExecute());
    }

    SECTION("hook recv") {
        dyno::x86Detour detour{(uintptr_t) &recv, (uintptr_t)h_hookRecv, &hookRecvTramp);
        REQUIRE(detour.hook() == true);
    }

    SECTION("queue apc thread") {
        dyno::x86Detour detour{(uintptr_t)pNtQueueApcthread, (uintptr_t)h_NtQueueapcThread, &hkNtQueueapcThread);
        effects.push(); // catch does some allocations, push effect first so peak works
        REQUIRE(detour.hook() == true);
    }*/
}