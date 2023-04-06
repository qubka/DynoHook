#include "x86MsFastcall.hpp"

#ifdef ENV32BIT

using namespace dyno;

x86MsFastcall::x86MsFastcall(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment) :
        x86MsStdcall{std::move(arguments), returnType, alignment} {
    // Don't force the register on the user.
    // Why choose Fastcall if you set your own argument registers though..

    std::array<registers, 2> registers = { ECX, EDX };

    for (size_t i = 0, j = 0; i < m_Arguments.size(); ++i) {
        DataTypeSized& type = m_Arguments[i];

        // Floating should be on stack
        if (!type.isFloating()) {
            if (type.reg == NONE && j < registers.size()) {
                type.reg = registers[j++];
            }
        }
    }

    init();
}

x86MsFastcall::~x86MsFastcall() {

}

#endif // ENV32BIT