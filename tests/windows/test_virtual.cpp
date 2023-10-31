#include <catch2/catch_test_macros.hpp>

#if DYNO_ARCH_X86 == 32
#include "dynohook/conventions/x86/x86MsThiscall.h"
#define DEFAULT_CALLCONV dyno::x86MsThiscall
#elif DYNO_ARCH_X86 == 64
#include "dynohook/conventions/x64_ms_fastcall.h"
#define DEFAULT_CALLCONV dyno::x64MsFastCall
#endif
#include "dynohook/virtuals/vtable.h"
#include "dynohook/tests/stack_canary.h"
#include "dynohook/tests/effect_tracker.h"
#include "dynohook/os.h"

class VirtualTest {
public:
    VirtualTest() = default;
    virtual ~VirtualTest() = default;

    virtual int DYNO_THISCALL NoParamVirt() {
        return 4;
    }

    virtual int DYNO_THISCALL NoParamVirt2() {
        return 7;
    }
};

dyno::EffectTracker vTblSwapEffects;

TEST_CASE("VTableSwap tests", "[VTableSwap]") {
    std::unique_ptr<VirtualTest> ClassToHook = std::make_unique<VirtualTest>();

    dyno::VHookCache cache;
    dyno::VTable table{ClassToHook.get(), cache};

    /*SECTION("Verify vtable hook") {
        dyno::ConvFunc callConvInt = []{ return new DEFAULT_CALLCONV({}, dyno::DataType::Int32); };

        auto PreNoParamVirt = +[](dyno::CallbackType type, dyno::Hook& hook) {
            DYNO_UNUSED(type);
            DYNO_UNUSED(hook);
            dyno::StackCanary canary;
            std::cout << "PreNoParamVirt 1 Called!" << std::endl;
            vTblSwapEffects.peak().trigger();
            return dyno::ReturnAction::Handled;
        };

        auto PostNoParamVirt = +[](dyno::CallbackType type, dyno::Hook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            std::cout << "PostNoParamVirt 1 Called!" << std::endl;
            int return_value = hook.getReturnValue<int>();
            if (return_value == 4) {
                vTblSwapEffects.peak().trigger();
            }
            hook.setReturnValue<int>(1337);
            return dyno::ReturnAction::Handled;
        };

        dyno::StackCanary canary;
        auto hook = table.hook(1, callConvInt);
        REQUIRE(hook);
        hook->addCallback(dyno::CallbackType::Pre, PreNoParamVirt);
        hook->addCallback(dyno::CallbackType::Post, PostNoParamVirt);

        typedef int(DYNO_THISCALL *NoParamVirt)(void*);

        vTblSwapEffects.push();
        Force virtual table call
        void** vtable = *(void***)ClassToHook.get();
        auto noParamVirt = (NoParamVirt) vtable[1];
        int ret = noParamVirt(ClassToHook.get());

        REQUIRE(ret == 1337);
        REQUIRE(vTblSwapEffects.pop().didExecute(2));
        REQUIRE(table.unhook(1));
    }*/
}