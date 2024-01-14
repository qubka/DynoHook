#include <catch2/catch_test_macros.hpp>

#include "dynohook/detours/x64_detour.h"
#include "dynohook/tests/stack_canary.h"
#include "dynohook/tests/effect_tracker.h"
#include "dynohook/os.h"

#if DYNO_PLATFORM_WINDOWS
#include "dynohook/conventions/x64_windows_call.h"
#define DEFAULT_CALLCONV dyno::x64WindowsCall
#else
#include "dynohook/conventions/x64_systemV_call.h"
#define DEFAULT_CALLCONV dyno::x64SystemVcall
#endif

dyno::EffectTracker effectsNTD64;

DYNO_NOINLINE void hookMeInt(int a) {
    dyno::StackCanary canary;
    volatile int var = 1;
    int var2 = var + a;

    std::cout << var << " " << var2 << std::endl;
}

DYNO_NOINLINE void hookMeFloat(float a) {
    dyno::StackCanary canary;
    float ans = 1.0f;
    ans += a;
    
    std::cout << ans << " " << a << std::endl;
}

DYNO_NOINLINE void hookMeIntFloatDouble(int a, float b, double c) {
    dyno::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    
    std::cout << a << "" << b << " " << c << " " << ans << std::endl;
}

TEST_CASE("Simple Callback", "[AsmJit][Callback]") {
   
    SECTION("Integer argument") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int32}, dyno::DataType::Void); };

        auto preHookMeInt = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;

            if (hook.getArgument<int>(0) == 1337) {
                effectsNTD64.peak().trigger();
                std::cout << "preHookMeInt called" << std::endl;
            }

            return dyno::ReturnAction::Handled;
        };

        dyno::x64Detour detour((uintptr_t) &hookMeInt, callConv);
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Pre, preHookMeInt);

        effectsNTD64.push();
        hookMeInt(1337);
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }

    SECTION("Floating argument") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Float}, dyno::DataType::Void); };

        auto preHookMeFloat = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;

            if (hook.getArgument<float>(0) == 1337.1337f) {
                effectsNTD64.peak().trigger();
                std::cout << "preHookMeFloat called" << std::endl;
            }

            return dyno::ReturnAction::Handled;
        };

        dyno::x64Detour detour((uintptr_t) &hookMeFloat, callConv);
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Pre, preHookMeFloat);

        effectsNTD64.push();
        hookMeFloat(1337.1337f);
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }

    SECTION("Int, float, double arguments, string parsing types") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double}, dyno::DataType::Void); };

        auto preHookMeIntFloatDouble = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;

            auto a1 = hook.getArgument<int>(0);
            auto a2 = hook.getArgument<float>(1);
            auto a3 = hook.getArgument<double>(2);

            if (a1 == 1337 &&
                a2 == 1337.1337f &&
                a3 == 1337.1337) {
                effectsNTD64.peak().trigger();
                std::cout << "preHookMeIntFloatDouble called" << std::endl;
            }

            return dyno::ReturnAction::Handled;
        };

        dyno::x64Detour detour((uintptr_t) &hookMeIntFloatDouble, callConv);
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Pre, preHookMeIntFloatDouble);

        effectsNTD64.push();
        hookMeIntFloatDouble(1337, 1337.1337f, 1337.1337);
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }
}

DYNO_NOINLINE int rw_int(int a, float b, double c, int type) {
    DYNO_UNUSED(type);
    dyno::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
        effectsNTD64.peak().trigger();
    }
    std::cout << a << " " << b << " " << c << " " << ans << std::endl;
    return (int) ans;
}

DYNO_NOINLINE float rw_float(int a, float b, double c, int type) {
    DYNO_UNUSED(type);
    dyno::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
        effectsNTD64.peak().trigger();
    }
    std::cout << a << " " << b << " " << c << " " << ans << std::endl;
    return ans;
}

DYNO_NOINLINE double rw_double(int a, float b, double c, int type) {
    DYNO_UNUSED(type);
    dyno::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
        effectsNTD64.peak().trigger();
    }
    std::cout << a << " " << b << " " << c << " " << ans << std::endl;
    return ans;
}

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

DYNO_NOINLINE void rw_void(double a, double b, double c, double d, double e, double f, double g, double h, double i, double k) {
    dyno::StackCanary canary;
    volatile double ans = 0;
    ans += a;
    ans += b;
    ans += c;
    ans += d;
    ans += e;
    ans += f;
    ans += g;
    ans += h;
    ans += i;
    ans += k;
    if (isApproximatelyEqual(ans, 36.0)) {
        effectsNTD64.peak().trigger();
    }

    std::cout << a << " " << b << " " << c << " " << d << " " << e << " " << f << " " << g << " " << h << " " << i << " " << k << " " << ans << std::endl;
}

DYNO_NOINLINE long rw_long(long a, long b, long c, long d, long e, long f, long g, long h, long i, long k) {
    dyno::StackCanary canary;
    volatile long ans = 0;
    ans += a;
    ans += b;
    ans += c;
    ans += d;
    ans += e;
    ans += f;
    ans += g;
    ans += h;
    ans += i;
    ans += k;
    if (ans == 136) {
        effectsNTD64.peak().trigger();
    }

    std::cout << a << " " << b << " " << c << " " << d << " " << e << " " << f << " " << g << " " << h << " " << i << " " << k << " " << ans << std::endl;
    return ans;
}

TEST_CASE("Callback Argument re-writing", "[Convention]") {
    SECTION("Int, float, double arguments overwrite, int ret, host") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, dyno::DataType::Int32}, dyno::DataType::Int32); };

        auto pre_rw_int = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            
            hook.setArgument<int>(0, 5);
            hook.setArgument<float>(1, 5.0f);
            hook.setArgument<double>(2, 5.0);

            std::cout << "pre_rw_int called" << std::endl;

            return dyno::ReturnAction::Handled;
        };
        
        dyno::x64Detour detour((uintptr_t) &rw_int, callConv);
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Pre, pre_rw_int);

        effectsNTD64.push();
        int i = rw_int(1337, 1337.1337f, 1337.1337, 0);
        REQUIRE(i == 15);
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }

    SECTION("Int, float, double arguments overwrite, float ret, host") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, dyno::DataType::Int32}, dyno::DataType::Float); };
    
        auto pre_rw_float = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            
            hook.setArgument<int>(0, 5);
            hook.setArgument<float>(1, 5.0f);
            hook.setArgument<double>(2, 5.0);
            
            std::cout << "pre_rw_float called" << std::endl;
            
            return dyno::ReturnAction::Handled;
        };
    
        dyno::x64Detour detour((uintptr_t) &rw_float, callConv);
        REQUIRE(detour.hook() == true);
        
        detour.addCallback(dyno::CallbackType::Pre, pre_rw_float);

        effectsNTD64.push();
        float f = rw_float(1337, 1337.1337f, 1337.1337, 1);
        REQUIRE(isApproximatelyEqual(f, 15.0f));
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }

    SECTION("Int, float, double arguments overwrite, double ret, host") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, dyno::DataType::Int32}, dyno::DataType::Double); };

        auto pre_rw_double = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            
            hook.setArgument<int>(0, 5);
            hook.setArgument<float>(1, 5.0f);
            hook.setArgument<double>(2, 5.0);

            std::cout << "pre_rw_double called" << std::endl;

            return dyno::ReturnAction::Handled;
        };

        dyno::x64Detour detour((uintptr_t) &rw_double, callConv);
        REQUIRE(detour.hook() == true);
        
        detour.addCallback(dyno::CallbackType::Pre, pre_rw_double);

        effectsNTD64.push();
        double d = rw_double(1337, 1337.1337f, 1337.1337, 2);
        REQUIRE(isApproximatelyEqual(d, 15.0));
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }

    SECTION("Doubles arguments overwrite, void ret, host") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Double, dyno::DataType::Double, dyno::DataType::Double, dyno::DataType::Double, dyno::DataType::Double, dyno::DataType::Double, dyno::DataType::Double, dyno::DataType::Double, dyno::DataType::Double, dyno::DataType::Double}, dyno::DataType::Void); };

        auto pre_rw_void = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;

            hook.setArgument<double>(9, 0);

            std::cout << "pre_rw_void called" << std::endl;

            return dyno::ReturnAction::Handled;
        };

        dyno::x64Detour detour((uintptr_t) &rw_void, callConv);
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Pre, pre_rw_void);

        effectsNTD64.push();
        rw_void(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }

    SECTION("Longs arguments, long ret, host") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int64, dyno::DataType::Int64, dyno::DataType::Int64, dyno::DataType::Int64, dyno::DataType::Int64, dyno::DataType::Int64, dyno::DataType::Int64, dyno::DataType::Int64, dyno::DataType::Int64, dyno::DataType::Int64}, dyno::DataType::Int64); };

        auto pre_rw_long = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;

            hook.setArgument(9, 100);

            std::cout << "pre_rw_long called" << std::endl;

            return dyno::ReturnAction::Handled;
        };

        auto post_rw_long = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;

            hook.setReturnValue<long>(1337);

            std::cout << "post_rw_long called" << std::endl;

            return dyno::ReturnAction::Handled;
        };

        dyno::x64Detour detour((uintptr_t) &rw_long, callConv);
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Pre, pre_rw_long);
        detour.addCallback(dyno::CallbackType::Post, post_rw_long);

        effectsNTD64.push();
        long l = rw_long(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
        REQUIRE(l == 1337);
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }
}

TEST_CASE("Callback Return re-writing", "[Convention]") {
    SECTION("Int, float, double arguments, int ret overwrite, host") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, dyno::DataType::Int32}, dyno::DataType::Int32); };

        auto post_rw_int = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            
            hook.setReturnValue<int>(5);
            effectsNTD64.peak().trigger();
            std::cout << "post_rw_int called" << std::endl;

            return dyno::ReturnAction::Handled;
        };
        
        dyno::x64Detour detour((uintptr_t) &rw_int, callConv);
        REQUIRE(detour.hook() == true);

        detour.addCallback(dyno::CallbackType::Post, post_rw_int);

        effectsNTD64.push();
        int i = rw_int(1337, 1337.1337f, 1337.1337, 0);
        REQUIRE(i == 5);
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }

    SECTION("Int, float, double arguments, float ret overwrite, host") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, dyno::DataType::Int32}, dyno::DataType::Float); };
    
        auto post_rw_float = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            
            hook.setReturnValue<float>(5.0f);
            effectsNTD64.peak().trigger();
            std::cout << "post_rw_float called" << std::endl;

            return dyno::ReturnAction::Handled;
        };
    
        dyno::x64Detour detour((uintptr_t) &rw_float, callConv);
        REQUIRE(detour.hook() == true);
        
        detour.addCallback(dyno::CallbackType::Post, post_rw_float);

        effectsNTD64.push();
        float f = rw_float(1337, 1337.1337f, 1337.1337, 1);
        REQUIRE(f == 5.0f);
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }

    SECTION("Int, float, double arguments, double ret overwrite, host") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, dyno::DataType::Int32}, dyno::DataType::Double); };

        auto post_rw_double = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;
            
            hook.setReturnValue<double>(5.0);
            effectsNTD64.peak().trigger();
            std::cout << "post_rw_double called" << std::endl;

            return dyno::ReturnAction::Handled;
        };

        dyno::x64Detour detour((uintptr_t) &rw_double, callConv);
        REQUIRE(detour.hook() == true);
        
        detour.addCallback(dyno::CallbackType::Post, post_rw_double);

        effectsNTD64.push();
        double d = rw_double(1337, 1337.1337f, 1337.1337, 2);
        REQUIRE(d == 5.0);
        REQUIRE(effectsNTD64.pop().didExecute(1));
        REQUIRE(detour.unhook());
    }
}

DYNO_NOINLINE bool rw_bool(int a, float b, double c, int type) {
    DYNO_UNUSED(type);
    dyno::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    effectsNTD64.peak().trigger();
    
    std::cout << a << " " << b << " " << c << " " << ans << std::endl;
    return true;
}

TEST_CASE("Callback Skip original function", "[Convention]") {
    SECTION("Int, float, double arguments, bool ret, supercede host") {
        dyno::StackCanary canary;
        dyno::ConvFunc callConv = []{ return new DEFAULT_CALLCONV({dyno::DataType::Int32, dyno::DataType::Float, dyno::DataType::Double, dyno::DataType::Int32}, dyno::DataType::Bool); };
    
        auto pre_rw_bool = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            DYNO_UNUSED(hook);
            dyno::StackCanary canary;

            std::cout << "pre_rw_bool called" << std::endl;
            
            return dyno::ReturnAction::Supercede;
        };
        
        auto post_rw_bool = +[](dyno::CallbackType type, dyno::IHook& hook) {
            DYNO_UNUSED(type);
            dyno::StackCanary canary;

            hook.setReturnValue<bool>(false);

            std::cout << "post_rw_bool called" << std::endl;
            
            return dyno::ReturnAction::Handled;
        };
    
        dyno::x64Detour detour((uintptr_t) &rw_bool, callConv);
        REQUIRE(detour.hook() == true);
        
        detour.addCallback(dyno::CallbackType::Pre, pre_rw_bool);
        detour.addCallback(dyno::CallbackType::Post, post_rw_bool);

        effectsNTD64.push();
        bool b = rw_bool(1337, 1337.1337f, 1337.1337, 1);
        REQUIRE(b == false);
        REQUIRE(effectsNTD64.pop().didExecute(0));
        REQUIRE(detour.unhook());
    }
}