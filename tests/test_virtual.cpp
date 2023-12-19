#include <catch2/catch_test_macros.hpp>

#include "dynohook/virtuals/vtable.h"
#include "dynohook/tests/stack_canary.h"
#include "dynohook/tests/effect_tracker.h"
#include "dynohook/os.h"

#if DYNO_ARCH_X86 == 32
#if DYNO_PLATFORM_WINDOWS
#include "dynohook/conventions/x86_ms_thiscall.h"
#define DEFAULT_CALLCONV dyno::x86MsThiscall
#else
#include "dynohook/conventions/x86_gcc_thiscall.h"
#define DEFAULT_CALLCONV dyno::x86GccThiscall
#endif
#elif DYNO_ARCH_X86 == 64
#if DYNO_PLATFORM_WINDOWS
#include "dynohook/conventions/x64_ms_fastcall.h"
#define DEFAULT_CALLCONV dyno::x64MsFastCall
#else
#include "dynohook/conventions/x64_systemV_call.h"
#define DEFAULT_CALLCONV dyno::x64SystemVcall
#endif
#endif

struct TestStruct {
    int a;
    int b;
    int c;
    int d;
    int e;
    float f;
    double g;
};

dyno::EffectTracker vTblSwapEffects;

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

    virtual float DYNO_THISCALL MultParamVirt3(int a, float b, double c, TestStruct d, std::string e, float f, void* g) {
        DYNO_UNUSED(d);
        dyno::StackCanary canary;
        volatile float ans = 0.0f;
        ans += (float) (a * 3);
        ans += b;
        ans += (float) c;
        ans += (float) f;
        std::cout << e << std::endl;
        if (g == nullptr)
            vTblSwapEffects.peak().trigger();
        return ans;
    }
};

TEST_CASE("VTableSwap tests", "[VTableSwap]") {
    std::unique_ptr<VirtualTest> ClassToHook = std::make_unique<VirtualTest>();

    dyno::VHookCache cache;
    dyno::VTable table{ClassToHook.get(), cache};

    SECTION("Verify vtable hook") {
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
        //Force virtual table call
        void** vtable = *(void***) ClassToHook.get();
        auto noParamVirt = (NoParamVirt) vtable[1];
        int ret = noParamVirt(ClassToHook.get());

        REQUIRE(ret == 1337);
        REQUIRE(vTblSwapEffects.pop().didExecute(2));
        REQUIRE(table.unhook(1));
    }

    SECTION("Verify multiple callbacks") {
        dyno::ConvFunc callConvFloat = []{
            return new DEFAULT_CALLCONV({dyno::DataType::Pointer, dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, dyno::DataType::Pointer, dyno::DataType::String, dyno::DataType::Float, dyno::DataType::Pointer}, dyno::DataType::Float);
        };

        auto PreMultParamVirt = +[](dyno::CallbackType type, dyno::Hook& hook) {
            DYNO_UNUSED(type);
            DYNO_UNUSED(hook);
            dyno::StackCanary canary;

            auto arg0 = hook.getArgument<VirtualTest*>(0);
            auto arg1 = hook.getArgument<int>(1);
            auto arg2 = hook.getArgument<float>(2);
            auto arg3 = hook.getArgument<double>(3);
            auto arg4 = hook.getArgument<TestStruct*>(4);
            auto arg5 = hook.getArgument<std::string*>(5);
            auto arg6 = hook.getArgument<float>(6);
            auto arg7 = hook.getArgument<uintptr_t>(7);

            std::cout << "PreMultParamVirt 3 Called!" << std::endl;
            vTblSwapEffects.peak().trigger();
            return dyno::ReturnAction::Handled;
        };


        auto PostMultParamVirt = +[](dyno::CallbackType type, dyno::Hook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            std::cout << "PostMultParamVirt 3 Called!" << std::endl;
            int return_value = hook.getReturnValue<int>();
            if (return_value == 4) {
                vTblSwapEffects.peak().trigger();
            }
            hook.setReturnValue<int>(1337);
            return dyno::ReturnAction::Handled;
        };

        dyno::StackCanary canary;
        auto hook = table.hook(3, callConvFloat);
        REQUIRE(hook);
        hook->addCallback(dyno::CallbackType::Pre, PreMultParamVirt);
        hook->addCallback(dyno::CallbackType::Post, PostMultParamVirt);

        typedef float(DYNO_THISCALL *MultParamVirt)(void*, int, float, double, TestStruct, std::string, float, void*);

        TestStruct test{1, 2, 3, 4, 5, 6.0f, 7.0};

        vTblSwapEffects.push();
        //Force virtual table call
        void** vtable = *(void***) ClassToHook.get();
        auto noParamVirt = (MultParamVirt) vtable[3];
        float ret = noParamVirt(ClassToHook.get(), 1, 2.0f, 3.0f, test, "test", 4.0f, &canary);

        REQUIRE(ret == 7.0f);
        REQUIRE(vTblSwapEffects.pop().didExecute(3));
        REQUIRE(table.unhook(3));
    }
}