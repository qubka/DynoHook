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

#include <cmath>

template<typename T>
bool isApproximatelyEqual(T a, T b, T tolerance = std::numeric_limits<T>::epsilon()) {
    T diff = std::fabs(a - b);
    if (diff <= tolerance)
        return true;

    if (diff < std::fmax(std::fabs(a), std::fabs(b)) * tolerance)
        return true;

    return false;
}

TEST_CASE("VTableSwap tests", "[VTableSwap]") {
    std::unique_ptr<VirtualTest> ClassToHook = std::make_unique<VirtualTest>();

    dyno::VHookCache cache;
    dyno::VTable table{ClassToHook.get(), cache};

    SECTION("Verify vtable hook") {
        dyno::ConvFunc callConvInt = []{ return new DEFAULT_CALLCONV({}, dyno::DataType::Int32); };

        auto PreNoParamVirt = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            DYNO_UNUSED(hook);
            dyno::StackCanary canary;
            std::cout << "PreNoParamVirt 1 Called!" << std::endl;
            vTblSwapEffects.peak().trigger();
            return dyno::ReturnAction::Handled;
        };

        auto PostNoParamVirt = +[](dyno::CallbackType type, dyno::IHook& hook) {
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
        auto hook = table.hook(0, callConvInt);
        REQUIRE(hook);
        hook->addCallback(dyno::CallbackType::Pre, PreNoParamVirt);
        hook->addCallback(dyno::CallbackType::Post, PostNoParamVirt);

        typedef int(DYNO_THISCALL *NoParamVirt)(void*);

        vTblSwapEffects.push();
        //Force virtual table call
        void** vtable = *(void***) ClassToHook.get();
        auto noParamVirt = (NoParamVirt) vtable[0];
        int ret = noParamVirt(ClassToHook.get());

        REQUIRE(ret == 1337);
        REQUIRE(vTblSwapEffects.pop().didExecute(2));
        REQUIRE(table.unhook(0));
    }

    SECTION("Verify multiple callbacks") {
        dyno::ConvFunc callConvFloat = []{
#if DYNO_ARCH_X86 == 64
            return new DEFAULT_CALLCONV({dyno::DataType::Pointer, dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, dyno::DataType::Pointer, dyno::DataType::String, dyno::DataType::Float, dyno::DataType::Pointer}, dyno::DataType::Float);
#elif DYNO_ARCH_X86 == 32
            /* Inlined objects into stack */
            dyno::DataObject testStruct {
                dyno::DataType::Object,
                dyno::RegisterType::NONE,
                32
            };
            dyno::DataObject strStruct {
                dyno::DataType::Object,
                dyno::RegisterType::NONE,
                28
            };
            return new DEFAULT_CALLCONV({dyno::DataType::Pointer, dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, testStruct, strStruct, dyno::DataType::Float, dyno::DataType::Pointer}, dyno::DataType::Float);
#endif // DYNO_ARCH_X86
        };

        auto PreMultParamVirt = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            DYNO_UNUSED(hook);
            dyno::StackCanary canary;

#if DYNO_ARCH_X86 == 64
            auto arg0 = hook.getArgument<VirtualTest*>(0);
            auto arg1 = hook.getArgument<int>(1);
            auto arg2 = hook.getArgument<float>(2);
            auto arg3 = hook.getArgument<double>(3);
            auto arg4 = *hook.getArgument<TestStruct*>(4);
            auto arg5 = *hook.getArgument<std::string*>(5);
            auto arg6 = hook.getArgument<float>(6);
            auto arg7 = hook.getArgument<uintptr_t>(7);
#elif DYNO_ARCH_X86 == 32
            auto arg0 = hook.getArgument<VirtualTest*>(0);
            auto arg1 = hook.getArgument<int>(1);
            auto arg2 = hook.getArgument<float>(2);
            auto arg3 = hook.getArgument<double>(3);
            auto arg4 = hook.getArgument<TestStruct>(4);
            auto arg5 = hook.getArgument<std::string>(5);
            auto arg6 = hook.getArgument<float>(6);
            auto arg7 = hook.getArgument<uintptr_t>(7);
#endif // DYNO_ARCH_X86
            // Check arguments
            REQUIRE(arg4.a == 1);
            REQUIRE(arg4.b == 2);
            REQUIRE(arg4.c == 3);
            REQUIRE(arg4.d == 4);
            REQUIRE(arg4.e == 5);
            REQUIRE(arg4.f == 6.0f);
            REQUIRE(arg4.g == 7.0);
            REQUIRE(arg1 == 1);
            REQUIRE(arg2 == 2.0f);
            REQUIRE(arg3 == 3.0);
            REQUIRE(arg5 == "test");
            REQUIRE(arg6 == 4.0f);

            std::cout << "PreMultParamVirt 3 Called!" << std::endl;
            vTblSwapEffects.peak().trigger();
            return dyno::ReturnAction::Handled;
        };


        auto PostMultParamVirt = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            std::cout << "PostMultParamVirt 3 Called!" << std::endl;
            float return_value = hook.getReturnValue<float>();
            if (isApproximatelyEqual(return_value, 12.0f)) {
                vTblSwapEffects.peak().trigger();
            }
            hook.setReturnValue<float>(13.37f);
            return dyno::ReturnAction::Handled;
        };

        auto PostMultParamVirt2 = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            std::cout << "PostMultParamVirt(2) 3 Called!" << std::endl;
            float return_value = hook.getReturnValue<float>();
            if (isApproximatelyEqual(return_value, 13.37f)) {
                vTblSwapEffects.peak().trigger();
            }
            hook.setReturnValue<float>(7.0f);
            return dyno::ReturnAction::Handled;
        };

        dyno::StackCanary canary;
        auto hook = table.hook(2, callConvFloat);
        REQUIRE(hook);
        hook->addCallback(dyno::CallbackType::Pre, PreMultParamVirt);
        hook->addCallback(dyno::CallbackType::Post, PostMultParamVirt);
        hook->addCallback(dyno::CallbackType::Post, PostMultParamVirt2);

        typedef float(DYNO_THISCALL *MultParamVirt)(void*, int, float, double, TestStruct, std::string, float, void*);

        TestStruct test{1, 2, 3, 4, 5, 6.0f, 7.0};

        vTblSwapEffects.push();
        //Force virtual table call
        void** vtable = *(void***) ClassToHook.get();
        auto MultParamVirt3 = (MultParamVirt) vtable[2];
        float ret = MultParamVirt3(ClassToHook.get(), 1, 2.0f, 3.0, test, "test", 4.0f, &canary);

        REQUIRE(isApproximatelyEqual(ret, 7.0f));
        REQUIRE(vTblSwapEffects.pop().didExecute(3));
        REQUIRE(table.unhook(2));
    }
}