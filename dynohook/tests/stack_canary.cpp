#include "dynohook/tests/stack_canary.h"

#include <exception>

using namespace dyno;

StackCanary::StackCanary() {
    for (uint8_t& i : buf) {
        i = 0xCE;
    }
}

bool StackCanary::isStackGood() {
    for (uint8_t i : buf) {
        if (i != 0xCE)
            return false;
    }
    return true;
}

StackCanary::~StackCanary() noexcept(false) {
    if (!isStackGood())
        throw std::runtime_error("Stack corruption detected");
}