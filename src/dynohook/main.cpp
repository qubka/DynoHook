#include "x64_detour.h"

#include <iostream>

int Callback(int x, int y) {
    std::cout << "Callback" << std::endl;
    std::cout << "Callback" << std::endl;
    std::cout << "Callback" << std::endl;
    std::cout << "Callback" << std::endl;
    std::cout << "Callback" << std::endl;

    return 12;
}

int MyFunc(int x, int y) {
    std::cout << "MyFunc" << std::endl;
    return x + y;
}

int main(int argc, char* argv[]) {
    std::cout << "MyFunc" << std::endl;

    //MyFunc(1, 3);

    uint64_t holder;

    auto yy = &MyFunc;

    dyno::x64Detour detour{(uint64_t)&MyFunc, (uint64_t)&Callback, &holder};
    detour.hook();

    auto a = MyFunc(1, 3);

    std::cout << a << std::endl;

    return 0;
}