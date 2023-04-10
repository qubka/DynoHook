#include "x86MsFastcall.hpp"

#ifdef ENV32BIT

using namespace dyno;

x86MsFastcall::x86MsFastcall(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment) :
        x86MsStdcall{std::move(arguments), returnType, alignment} {

    // Don't force the register on the user.
    RegisterType registers[] = { ECX, EDX };

    for (size_t i = 0, j = 0; i < m_arguments.size(); ++i) {
        DataTypeSized& arg = m_arguments[i];

        // Floating should be on stack
        if (arg.reg == NONE && !arg.isFlt() && j < 2)
            arg.reg = registers[j++];
    }

    init();
}

x86MsFastcall::~x86MsFastcall() {
}

#endif // ENV32BIT