# DynoHook
## Introduction
DynoHooks is a versatile and powerful C++ library designed to provide developers with an easy way to create dynamic function hooks for any call convention with pre and post callbacks. This library is built using AsmJit machine code generation library and Capstone Disassembler library to achieve dynamic function hooking for x86 architecture with support for 32/64-bit modes on Windows and Linux platforms. The library is designed to be used with C++17 or later. It is based on Ayuto's DynamicHooks library.

Dynamic function hooks are a powerful tool in the arsenal of software developers, as they allow developers to modify the behavior of a function without the need to modify the original code. This is particularly useful in situations where the code is not under the control of the developer or where modifying the original code is not feasible. For example, developers can use dynamic function hooks to debug, profile, or optimize their applications.

DynoHooks offers a simple and intuitive API that makes it easy for developers to add hooks to any function on runtime, including those in third-party libraries. To create a hook, developers provide information about the function pointer and argument and return types for call convention class. Then, DynoHooks generates the necessary machine code to intercept and fully modify the function call or even block execution of original function.

The library comes with pre and post callbacks, enabling developers to catch the behavior of the function before and after its execution. In addition, this allows developers to implement a wide range of use cases, such as logging, tracing, and error handling. Also, the pre and post callback functions used to modify the input and output parameters of the function call.

Libray supports different call conventions, such as *__cdecl*, *__stdcall*, *__fastcall* and *__vectorcall* and other modern x64 call conventions. Developers can customize the callback functions based on their specific use case, and they can choose to override or supplement the behavior of the original function.

Another unique features of DynoHooks is the ability to handle return values from the hooked function callbacks. The library provides return action feature, which defines the possible actions that the callback function can take with respect to the return value. The ReturnAction can be set to Ignored, Handled, Override, or Supercede, depending on the desired behavior.

## Advantages
One of the key advantages of DynoHook library over other function hooking implementations is its ability to dynamically create hooks at runtime without requiring knowledge of the function prototype at compile time. Instead, developers only need to provide the address of the function, the argument types, the return type, and the call convention. This feature allows developers to create hooks for functions in third-party libraries, which they may not have access to the source code or the function prototypes. Additionally, DynoHook's dynamic approach makes it well-suited for use in embedded systems, where there may be limited access to C++ features at compile time. This flexibility and versatility make DynoHook an attractive option for developers looking to modify program behavior in real-time, without having to modify the original code or rely on static hooking implementations.

## Requirements
This module requires the following modules:

- [AsmJit](https://asmjit.com/)
- [Capstone](https://www.capstone-engine.org/)

## Examples
### Static functions
```c++
int g_iMyFuncCallCount = 0;
int g_iPreMyFuncCallCount = 0;
int g_iPostMyFuncCallCount = 0;

using namespace dyno;

int __fastcall MyFunc(int x, int y) {
	g_iMyFuncCallCount++;
	assert(x == 3);
	assert(y == 10);

	int result = x + y;
	assert(result == 13);

	return result;
}

ReturnAction PreMyFunc(HookType hookType, Hook& hook) {
	g_iPreMyFuncCallCount++;
	int x = hook.getArgument<int>(0);
	assert(x == 3);

	int y = hook.getArgument<int>(1);
	assert(y == 10);

	return ReturnAction::Ignored;
}

ReturnAction PostMyFunc(HookType hookType, Hook& hook) {
	g_iPostMyFuncCallCount++;
	int x = hook.getArgument<int>(0);
	assert(x == 3);

	int y = hook.getArgument<int>(1);
	assert(y == 10);

	int return_value = hook.getReturnValue<int>();
	assert(return_value == 13);

	hook.setReturnValue<int>(1337);

	return ReturnAction::Ignored;
}

void main() {
	HookManager& hookMngr = HookManager::Get();

	// Hook the function
	Hook* pHook = hookMngr.hook((void *) &MyFunc, new x64MsFastcall({DATA_TYPE_INT, DATA_TYPE_INT}, DATA_TYPE_INT));

	// Add the callbacks
	pHook->addCallback(HookType::Pre, (HookHandler *) (void *) &PreMyFunc);
	pHook->addCallback(HookType::Post, (HookHandler *) (void *) &PostMyFunc);

	// Call the function
	int ret = MyFunc(3, 10);

	assert(g_iMyFuncCallCount == 1);
	assert(g_iPreMyFuncCallCount == 1);
	assert(g_iPostMyFuncCallCount == 1);
	assert(ret == 1337);

	hookMngr.unhookAll();
}
```
### Member functions
```c++
int g_iMyFuncCallCount = 0;
int g_iPreMyFuncCallCount = 0;
int g_iPostMyFuncCallCount = 0;

using namespace dyno;

class MyClass;
MyClass* g_pMyClass = nullptr;

class MyClass {
public:
	MyClass() : m_iData{0} {}

	int __fastcall myFunc(int x, int y) {
		g_iMyFuncCallCount++;
		assert(this == g_pMyClass);
		assert(x == 3);
		assert(y == 10);

		int result = x + y;
		assert(result == 13);

		m_iData++;

		return result;
	}
private:
	int m_iData;
};

ReturnAction PreMyFunc(HookType hookType, Hook& hook) {
	g_iPreMyFuncCallCount++;
	MyClass* pMyClass = hook.getArgument<MyClass *>(0);
	assert(pMyClass == g_pMyClass);

	int x = hook.getArgument<int>(1);
	assert(x == 3);

	int y = hook.getArgument<int>(2);
	assert(y == 10);

	return ReturnAction::Ignored;
}

ReturnAction PostMyFunc(HookType hookType, Hook& hook) {
	g_iPostMyFuncCallCount++;
	MyClass* pMyClass = hook.getArgument<MyClass *>(0);
	assert(pMyClass == g_pMyClass);

	int x = hook.getArgument<int>(1);
	assert(x == 3);

	int y = hook.getArgument<int>(2);
	assert(y == 10);

	int return_value = hook.getReturnValue<int>();
	assert(return_value == 13);

	hook.setReturnValue<int>(1337);

	return ReturnAction::Ignored;
}

void main() {
	HookManager& hookMngr = HookManager::Get();

	int (__fastcall MyClass::*myFunc)(int, int) = &MyClass::myFunc;

	// Hook the function
	Hook* pHook = hookMngr.hook((void *&) myFunc, new x64MsFastcall({DATA_TYPE_POINTER, DATA_TYPE_INT, DATA_TYPE_INT}, DATA_TYPE_INT));

	// Add the callbacks
	pHook->addCallback(HookType::Pre, (HookHandler *) (void *) &PreMyFunc);
	pHook->addCallback(HookType::Post, (HookHandler *) (void *) &PostMyFunc);

	MyClass a;
	g_pMyClass = &a;

	// Call the function
	int ret = a.myFunc(3, 10);

	assert(g_iMyFuncCallCount == 1);
	assert(g_iPreMyFuncCallCount == 1);
	assert(g_iPostMyFuncCallCount == 1);
	assert(ret == 1337);

	hookMngr.unhookAll();
}
```

## Build
```
git clone https://github.com/qubka/DynoHook.git
cd ./DynoHook
git submodule update --init --recursive
mkdir build
cd build
cmake -G "Visual Studio 15 2017" ..
```

## Credits
- [Ayuto](https://github.com/Ayuto/) - DynamicHooks library
- [peace-maker](https://github.com/peace-maker) - DHooks with detour support
- [Kailo](https://github.com/Kailo97) - Help with assembly porting from x32 to x64 and f

## Links
- [X64 Function Hooking by Example](http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html)
- [Ayuto's DynamicHooks x32 Library](https://github.com/Ayuto/DynamicHooks)
- [Sourcemod's DHook extention](https://forums.alliedmods.net/showpost.php?p=2588686&postcount=589)lliedmods.net/showpost.php?p=2588686&postcount=589)