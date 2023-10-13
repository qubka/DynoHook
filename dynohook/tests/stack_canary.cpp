#include "dynohook/tests/stack_canary.h"

using namespace dyno;

StackCanary::StackCanary() {
	for (int i = 0; i < sizeof(buf); i++) {
		buf[i] = 0xCE;
	}
}

bool StackCanary::isStackGood() {
	for (int i = 0; i < sizeof(buf); i++) {
		if (buf[i] != 0xCE)
			return false;
	}
	return true;
}

StackCanary::~StackCanary() noexcept(false) {
	if (!isStackGood())
		throw "Stack corruption detected";
}