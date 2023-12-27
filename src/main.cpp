#include <dynohook/detours/x64_detour.h>
#include <dynohook/conventions/x64_windows_call.h>

#include <iostream>

int g_MyFuncCallCount = 0;
int g_PreMyFuncCallCount = 0;
int g_PostMyFuncCallCount = 0;

using namespace dyno;

DYNO_NOINLINE int MyFunc(int x, int y) {
    g_MyFuncCallCount++;
    assert(x == 3);
    assert(y == 10);

    int result = x + y;
    assert(result == 13);

    return result;
}

ReturnAction PreMyFunc(CallbackType hookType, Hook& hook) {
    g_PreMyFuncCallCount++;
    int x = hook.getArgument<int>(0);
    assert(x == 3);

    int y = hook.getArgument<int>(1);
    assert(y == 10);

    return ReturnAction::Handled;
}

ReturnAction PostMyFunc(CallbackType hookType, Hook& hook) {
    g_PostMyFuncCallCount++;
    int x = hook.getArgument<int>(0);
    assert(x == 3);

    int y = hook.getArgument<int>(1);
    assert(y == 10);

    int return_value = hook.getReturnValue<int>();
    assert(return_value == 13);

    hook.setReturnValue<int>(1337);

    return ReturnAction::Ignored;
}


int main(int argc, char* argv[]) {
    auto yy = &MyFunc;

    dyno::x64Detour detour{(uintptr_t)&MyFunc, [] { return new x64WindowsCall({DataType::Int, DataType::Int}, DataType::Int); }};
    detour.hook();

    // add the callbacks
    detour.addCallback(CallbackType::Pre, (CallbackHandler*) &PreMyFunc);
    detour.addCallback(CallbackType::Post, (CallbackHandler*) &PostMyFunc);

    // call the function
    int ret = MyFunc(3, 10);

    assert(g_MyFuncCallCount == 1);
    assert(g_PreMyFuncCallCount == 1);
    assert(g_PostMyFuncCallCount == 1);
    assert(ret == 1337);

    return 0;
}