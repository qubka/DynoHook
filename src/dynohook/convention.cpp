#include "convention.h"

using namespace dyno;

CallingConvention::CallingConvention(std::vector<DataObject> arguments, DataObject returnType, size_t alignment) :
    m_arguments(std::move(arguments)),
    m_return(returnType),
    m_alignment(alignment),
    m_stackSize(0),
    m_registerSize(0) {
}

void CallingConvention::init() {
    m_stackSize = 0;
    m_registerSize = 0;

    for (auto& [type, reg, size] : m_arguments) {
        if (!size)
            size = GetDataTypeSize(type, m_alignment);

        if (reg == NONE)
            m_stackSize += size;
        else
            m_registerSize += size;
    }

    if (!m_return.size)
        m_return.size = GetDataTypeSize(m_return.type, m_alignment);
}

void CallingConvention::saveReturnValue(const Registers& registers) {
    std::unique_ptr<uint8_t[]> savedReturnValue = std::make_unique<uint8_t[]>(m_return.size);
    std::memcpy(savedReturnValue.get(), getReturnPtr(registers), m_return.size);
    m_savedReturnBuffers.push_back(std::move(savedReturnValue));
}

void CallingConvention::restoreReturnValue(const Registers& registers) {
    uint8_t* savedReturnValue = m_savedReturnBuffers.back().get();
    std::memcpy(getReturnPtr(registers), savedReturnValue, m_return.size);
    onReturnPtrChanged(registers, savedReturnValue);
    m_savedReturnBuffers.pop_back();
}

void CallingConvention::saveCallArguments(const Registers& registers) {
    size_t argTotalSize = getArgStackSize() + getArgRegisterSize();
    std::unique_ptr<uint8_t[]> savedCallArguments = std::make_unique<uint8_t[]>(argTotalSize);
    size_t offset = 0;
    for (size_t i = 0; i < m_arguments.size(); ++i) {
        size_t size = m_arguments[i].size;
        std::memcpy(savedCallArguments.get() + offset, getArgumentPtr(i, registers), size);
        offset += size;
    }
    m_savedCallArguments.push_back(std::move(savedCallArguments));
}

void CallingConvention::restoreCallArguments(const Registers& registers) {
    uint8_t* savedCallArguments = m_savedCallArguments.back().get();
    size_t offset = 0;
    for (size_t i = 0; i < m_arguments.size(); ++i) {
        size_t size = m_arguments[i].size;
        std::memcpy(getArgumentPtr(i, registers), (savedCallArguments + offset), size);
        offset += size;
    }
    m_savedCallArguments.pop_back();
}
