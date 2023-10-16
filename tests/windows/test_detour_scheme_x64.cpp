#include <catch2/catch_test_macros.hpp>

#include "dynohook/detours/x64_detour.h"
#include "dynohook/conventions/x64/x64MsFastcall.h"
#include "dynohook/tests/stack_canary.h"
#include "dynohook/tests/effect_tracker.h"
#include "dynohook/os.h"

TEST_CASE("Testing detour schemes", "[DetourScheme][ADetour]") {
	dyno::EffectTracker schemeEffects;
	
    typedef int (* IntFn)();

    asmjit::JitRuntime rt;

    auto make_func = [&](const std::function<void(asmjit::x86::Assembler&)>& builder) {
        asmjit::CodeHolder code;
        code.init(rt.environment(), rt.cpuFeatures());
        asmjit::x86::Assembler a{&code};
        builder(a);

        IntFn fn;
        auto error = rt.add(&fn, &code);

        if (error) {
            std::cerr << "Error generating function: " << asmjit::DebugUtils::errorAsString(error) << std::endl;
            exit(1);
        }

        return fn;
    };
	
	dyno::ConvFunc call_conv_ret_int = []{ return new dyno::x64MsFastcall({}, dyno::DataType::Int); };
	
    SECTION("Validate valloc2 scheme in function with translation and back-references") {
        dyno::StackCanary canary;

        auto valloc_function = make_func([](asmjit::x86::Assembler& a) {
            auto SetRax = a.newLabel();
            auto Exit = a.newLabel();

            a.cmp(asmjit::x86::qword_ptr(asmjit::x86::rip, -11), 0x12345678);

            a.bind(SetRax);
            a.cmp(asmjit::x86::rax, 0x1337);
            a.je(Exit);
            a.mov(asmjit::x86::rax, 0x1337);
            a.jmp(SetRax);

            a.bind(Exit);
            a.ret();
        });

		dyno::ReturnAction pre_hook_valloc_function(dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			ripEffects.peak().trigger();
			std::cout << "pre_hook_valloc_function called" std::endl;
			
			return dyno::ReturnAction::Handled;
		}

		dyno::ReturnAction post_hook_valloc_function(dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			ripEffects.peak().trigger();
			std::cout << "post_hook_valloc_function called" << std::endl;
			
			int return_value = hook.getReturnValue<int>();
			assert(return_value == 0x1337);

			return dyno::ReturnAction::Ignored;
		}
		
		detour.addCallback(dyno::CallbackType::Pre, (dyno::CallbackHandler*) &pre_hook_valloc_function);
		detour.addCallback(dyno::CallbackType::Post, (dyno::CallbackHandler*) &post_hook_valloc_function);

        dyno::x64Detour detour{(uintptr_t) valloc_function, call_conv_ret_int};
        detour.setDetourScheme(dyno::x64Detour::detour_scheme_t::VALLOC2);
        REQUIRE(detour.hook());
        schemeEffects.push();
        REQUIRE(valloc_function() == 0x1337);
        REQUIRE(schemeEffects.pop().didExecute(2));
        REQUIRE(detour.unhook());
    }

    SECTION("Validate in-place scheme in large function") {
        dyno::StackCanary canary;

        auto large_function = make_func([](auto& a) {
            a.mov(asmjit::x86::rax, 0x1234567890123456);
            a.mov(asmjit::x86::rbx, 0x6543210987654321);
            a.mov(asmjit::x86::rcx, 0x1234567890ABCDEF);
            a.mov(asmjit::x86::rcx, 0xFEDCBA0987654321);
            a.ret();
        });

		dyno::ReturnAction pre_hook_large_function(dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			ripEffects.peak().trigger();
			std::cout << "pre_hook_large_function called" std::endl;
			
			return dyno::ReturnAction::Handled;
		}

		dyno::ReturnAction post_hook_large_function(dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			ripEffects.peak().trigger();
			std::cout << "post_hook_large_function called" << std::endl;
			
			int return_value = hook.getReturnValue<int>();
			assert(return_value == 0x1234567890123456);

			return dyno::ReturnAction::Ignored;
		}
		
		detour.addCallback(dyno::CallbackType::Pre, (dyno::CallbackHandler*) &pre_hook_large_function);
		detour.addCallback(dyno::CallbackType::Post, (dyno::CallbackHandler*) &post_hook_large_function);

        dyno::x64Detour detour{(uintptr_t) large_function, call_conv_ret_int};
        detour.setDetourScheme(dyno::x64Detour::detour_scheme_t::INPLACE);
        REQUIRE(detour.hook());
        schemeEffects.push();
        large_function();
        REQUIRE(schemeEffects.pop().didExecute(2));
        REQUIRE(detour.unhook());
    }

    SECTION("Validate in-place scheme in medium function") {
        dyno::StackCanary canary;

        auto medium_function = make_func([](auto& a) {
            a.mov(asmjit::x86::rax, 0x1234567890123456);
            a.mov(asmjit::x86::rcx, 0x1234567890ABCDEF);
            a.ret();
        });

		dyno::ReturnAction pre_hook_medium_function(dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			ripEffects.peak().trigger();
			std::cout << "pre_hook_medium_function called" std::endl;
			
			return dyno::ReturnAction::Handled;
		}

		dyno::ReturnAction post_hook_medium_function(dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			ripEffects.peak().trigger();
			std::cout << "post_hook_medium_function called" << std::endl;
			
			int return_value = hook.getReturnValue<int>();
			assert(return_value == 0x1234567890123456);

			return dyno::ReturnAction::Ignored;
		}
		
		detour.addCallback(dyno::CallbackType::Pre, (dyno::CallbackHandler*) &pre_hook_medium_function);
		detour.addCallback(dyno::CallbackType::Post, (dyno::CallbackHandler*) &post_hook_medium_function);

        dyno::x64Detour detour1{(uintptr_t) medium_function, call_conv_ret_int};
        detour1.setDetourScheme(dyno::x64Detour::detour_scheme_t::INPLACE);
        REQUIRE(detour1.hook() == false);

        dyno::x64Detour detour2{(uintptr_t) medium_function, call_conv_ret_int};
        detour2.setDetourScheme(dyno::x64Detour::detour_scheme_t::INPLACE_SHORT);
        REQUIRE(detour2.hook());
        schemeEffects.push();
        medium_function();
        REQUIRE(schemeEffects.pop().didExecute(2));
        REQUIRE(detour2.unhook());
    }

    SECTION("Validate in-place scheme in function with translation") {
        dyno::StackCanary canary;

        auto rip_function = make_func([](asmjit::x86::Assembler& a) {
            a.cmp(asmjit::x86::qword_ptr(asmjit::x86::rip, -11), 0x12345678);
            a.mov(asmjit::x86::rax, 0x1337);
            a.ret();
        });

		dyno::ReturnAction pre_hook_rip_function(dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			ripEffects.peak().trigger();
			std::cout << "pre_hook_rip_function called" std::endl;
			
			return dyno::ReturnAction::Handled;
		}

		dyno::ReturnAction post_hook_rip_function(dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			ripEffects.peak().trigger();
			std::cout << "post_hook_rip_function called" << std::endl;
			
			int return_value = hook.getReturnValue<int>();
			assert(return_value == 0x1337);

			return dyno::ReturnAction::Ignored;
		}
		
		detour.addCallback(dyno::CallbackType::Pre, (dyno::CallbackHandler*) &pre_hook_rip_function);
		detour.addCallback(dyno::CallbackType::Post, (dyno::CallbackHandler*) &post_hook_rip_function);

        dyno::x64Detour detour{(uintptr_t) rip_function, call_conv_ret_int};
        detour.setDetourScheme(dyno::x64Detour::detour_scheme_t::INPLACE_SHORT);
        REQUIRE(detour.hook());
        schemeEffects.push();
        REQUIRE(rip_function() == 0x1337);
        REQUIRE(schemeEffects.pop().didExecute(2));
        REQUIRE(detour.unhook());
    }

    SECTION("Validate code-cave scheme in small function") {
        dyno::StackCanary canary;

        auto small_function = make_func([](auto& a) {
            a.mov(asmjit::x86::rax, 0x1234567890123456);
            a.ret();
        });

		dyno::ReturnAction pre_tramp_small_function(dyno::CallbackType type, dyno::Hook& hook) {
			dyno::StackCanary canary;
			ripEffects.peak().trigger();
			std::cout << "pre_tramp_small_function called" std::endl;
			
			return dyno::ReturnAction::Handled;
		}

        dyno::x64Detour detour1{(uintptr_t) small_function, call_conv_ret_int};
        detour1.setDetourScheme(dyno::x64Detour::detour_scheme_t::INPLACE_SHORT);
        REQUIRE(detour1.hook() == false);

        // TODO: Dyno is not guaranteed to find a cave, hence this test will often fail.
        // We need to find a way to deliberately reserve code cave.

        // dyno::x64Detour detour2((uintptr_t) small_function, call_conv_ret_int);
        // detour2.setDetourScheme(dyno::x64Detour::detour_scheme_t::CODE_CAVE);
        // REQUIRE(detour2.hook());
        // schemeEffects.push();
        // small_function();
        // REQUIRE(schemeEffects.pop().didExecute(1));
        // REQUIRE(detour2.unhook());
    }
}