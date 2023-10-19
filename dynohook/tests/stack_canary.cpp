#include "dynohook/tests/stack_canary.h"

using namespace dyno;

StackCanary::StackCanary() {
	for (unsigned char& i : buf) {
		i = 0xCE;
	}
}

bool StackCanary::isStackGood() {
	for (unsigned char i : buf) {
		if (i != 0xCE)
			return false;
	}
	return true;
}

StackCanary::~StackCanary() noexcept(false) {
	if (!isStackGood())
		throw std::exception("Stack corruption detected");
}