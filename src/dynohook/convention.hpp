#pragma once

#include "registers.hpp"

namespace dyno {
    enum DataType : uint8_t {
        DATA_TYPE_VOID,
        DATA_TYPE_BOOL,
        DATA_TYPE_CHAR,
        DATA_TYPE_UCHAR,
        DATA_TYPE_SHORT,
        DATA_TYPE_USHORT,
        DATA_TYPE_INT,
        DATA_TYPE_UINT,
        DATA_TYPE_LONG,
        DATA_TYPE_ULONG,
        DATA_TYPE_LONG_LONG,
        DATA_TYPE_ULONG_LONG,
        DATA_TYPE_FLOAT,
        DATA_TYPE_DOUBLE,
        DATA_TYPE_POINTER,
        DATA_TYPE_STRING,
        DATA_TYPE_M128,
        DATA_TYPE_M256,
        DATA_TYPE_M512,
        DATA_TYPE_OBJECT
    };

    struct DataTypeSized {
        DataType type;
        RegisterType reg;
        uint16_t size;

        DataTypeSized(DataType type, RegisterType reg = NONE, uint16_t size = 0) : type{type}, reg{reg}, size{size} {}

        bool isFloating() const { return type == DATA_TYPE_FLOAT || type == DATA_TYPE_DOUBLE; }
    };

    /**
     * Returns the size after applying alignment.
     * @param size The size that should be aligned.
     * @param alignment The alignment that should be used.
     * @return
     */
    inline size_t Align(size_t size, size_t alignment) {
        size_t unaligned = size % alignment;
        if (unaligned == 0)
            return size;

        return size + (alignment - unaligned);
    }

    /**
     * @brief Returns the size of a data type after applying alignment.
     * @param type The data type you would like to get the size of.
     * @param alignment The alignment that should be used.
     * @return
     */
    inline size_t GetDataTypeSize(DataTypeSized type, size_t alignment) {
        switch (type.type) {
            case DATA_TYPE_VOID:
                return 0;
            case DATA_TYPE_BOOL:
                return Align(sizeof(bool), alignment);
            case DATA_TYPE_CHAR:
                return Align(sizeof(char), alignment);
            case DATA_TYPE_UCHAR:
                return Align(sizeof(unsigned char), alignment);
            case DATA_TYPE_SHORT:
                return Align(sizeof(short), alignment);
            case DATA_TYPE_USHORT:
                return Align(sizeof(unsigned short), alignment);
            case DATA_TYPE_INT:
                return Align(sizeof(int), alignment);
            case DATA_TYPE_UINT:
                return Align(sizeof(unsigned int), alignment);
            case DATA_TYPE_LONG:
                return Align(sizeof(long), alignment);
            case DATA_TYPE_ULONG:
                return Align(sizeof(unsigned long), alignment);
            case DATA_TYPE_LONG_LONG:
                return Align(sizeof(long long), alignment);
            case DATA_TYPE_ULONG_LONG:
                return Align(sizeof(unsigned long long), alignment);
            case DATA_TYPE_FLOAT:
                return Align(sizeof(float), alignment);
            case DATA_TYPE_DOUBLE:
                return Align(sizeof(double), alignment);
            case DATA_TYPE_POINTER:
                return Align(sizeof(void*), alignment);
            case DATA_TYPE_STRING:
                return Align(sizeof(char*), alignment);
            case DATA_TYPE_M128:
                return Align(sizeof(float) * 4, alignment);
            case DATA_TYPE_M256:
                return Align(sizeof(float) * 8, alignment);
            case DATA_TYPE_M512:
                return Align(sizeof(float) * 16, alignment);
            case DATA_TYPE_OBJECT:
                return type.size;
            default:
                puts("Unknown data type.");
        }
        return 0;
    }

    /**
     * This is the base class for every calling convention.
     * Inherit from this class to create your own calling convention.
     */
    class ICallingConvention {
    public:
        /**
         * @brief Initializes the calling convention.
         * @param arguments A list of DataType_t objects, which define the arguments of the function.
         * @param returnType The return type of the function.
         * @param alignment
         */
        ICallingConvention(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment) :
            m_Arguments{std::move(arguments)},
            m_ReturnType{returnType},
            m_iAlignment{alignment} {
        }
        virtual ~ICallingConvention() = default;

        /**
         * @brief This should return a list of RegisterType values. These registers will be saved for later access.
         * @return
         */
        virtual std::vector<RegisterType> getRegisters() = 0;

        /**
         * Returns a pointer to the memory at the stack.
         * @param registers A snapshot of all saved registers.
         * @return
         */
        virtual void** getStackArgumentPtr(const Registers& registers) = 0;

        /**
         * @brief Returns a pointer to the argument at the given index.
         * @param index The index of the argument.
         * @param registers A snapshot of all saved registers.
         * @return
         */
        virtual void* getArgumentPtr(size_t index, const Registers& registers) = 0;

        /**
         * @brief
         * @param index The index of the argument.
         * @param registers A snapshot of all saved registers.
         * @param argumentPtr A pointer to the argument at the given index.
         */
        virtual void argumentPtrChanged(size_t index, const Registers& registers, void* argumentPtr) {
        }

        /**
         * @brief Returns a pointer to the return value.
         * @param registers A snapshot of all saved registers.
         * @return
         */
        virtual void* getReturnPtr(const Registers& registers) = 0;

        /**
         *
         * @param registers A snapshot of all saved registers.
         * @param returnPtr A pointer to the return value.
         */
        virtual void returnPtrChanged(const Registers& registers, void* returnPtr) {
        }

        /**
         * @brief Save the return value in a seperate buffer, so we can restore it after calling the original function.
         * @param registers A snapshot of all saved registers.
         */
        virtual void saveReturnValue(const Registers& registers) {
            std::unique_ptr<uint8_t[]> savedReturnValue = std::make_unique<uint8_t[]>(m_ReturnType.size);
            memcpy(savedReturnValue.get(), getReturnPtr(registers), m_ReturnType.size);
            m_SavedReturnBuffers.push_back(std::move(savedReturnValue));
        }

        /**
         * @brief
         * @param registers A snapshot of all saved registers.
         */
        virtual void restoreReturnValue(const Registers& registers) {
            uint8_t* savedReturnValue = m_SavedReturnBuffers.back().get();
            memcpy(getReturnPtr(registers), savedReturnValue, m_ReturnType.size);
            returnPtrChanged(registers, savedReturnValue);
            m_SavedReturnBuffers.pop_back();
        }

        /**
         * @brief Save the value of arguments in a seperate buffer for the post callback.
         * Compiler optimizations might cause the registers or stack space to be reused
         * and overwritten during function execution if the value isn't needed anymore
         * at some point. This leads to different values in the post hook.
         * @param registers A snapshot of all saved registers.
         */
        virtual void saveCallArguments(const Registers& registers) {
            size_t argTotalSize = getArgStackSize() + getArgRegisterSize();
            std::unique_ptr<uint8_t[]> savedCallArguments = std::make_unique<uint8_t[]>(argTotalSize);
            size_t offset = 0;
            for (size_t i = 0; i < m_Arguments.size(); ++i) {
                size_t size = m_Arguments[i].size;
                memcpy((void*) ((uintptr_t) savedCallArguments.get() + offset), getArgumentPtr(i, registers), size);
                offset += size;
            }
            m_SavedCallArguments.push_back(std::move(savedCallArguments));
        }

        /**
         * @brief Restore the value of arguments from a seperate buffer for the call.
         * @param registers A snapshot of all saved registers.
         */
        virtual void restoreCallArguments(const Registers& registers) {
            uint8_t* savedCallArguments = m_SavedCallArguments.back().get();
            size_t offset = 0;
            for (size_t i = 0; i < m_Arguments.size(); ++i) {
                size_t size = m_Arguments[i].size;
                memcpy(getArgumentPtr(i, registers), (void*) ((uintptr_t) savedCallArguments + offset), size);
                offset += size;
            }
            m_SavedCallArguments.pop_back();
        }

        /**
         * @brief Returns the number of bytes that should be added to the stack to clean up.
         * @return
         */
        virtual size_t getPopSize() {
            return 0;
        }

        /**
         * Returns the number of bytes for the buffer to store all the arguments that are passed in a stack in.
         * @return
         */
        size_t getArgStackSize() const {
            return m_iStackSize;
        }

        /**
         * @brief Returns the number of bytes for the buffer to store all the arguments that are passed in a register in.
         * @return
         */
        size_t getArgRegisterSize() const {
            return m_iRegisterSize;
        }

        const std::vector<DataTypeSized>& getArguments() const {
            return m_Arguments;
        }

        DataTypeSized getReturnType() const {
            return m_ReturnType;
        }

        size_t getAlignment() const {
            return m_iAlignment;
        }

    protected:
        void init() {
            m_iStackSize = 0;
            m_iRegisterSize = 0;

            for (auto& [type, reg, size] : m_Arguments) {
                if (!size)
                    size = GetDataTypeSize(type, m_iAlignment);

                if (reg == NONE)
                    m_iStackSize += size;
                else
                    m_iRegisterSize += size;
            }

            if (!m_ReturnType.size)
                m_ReturnType.size = GetDataTypeSize(m_ReturnType, m_iAlignment);
        }

    protected:
        std::vector<DataTypeSized> m_Arguments;
        DataTypeSized m_ReturnType;
        size_t m_iAlignment;
        size_t m_iStackSize;
        size_t m_iRegisterSize;

        // Save the return in case we call the original function and want to override the return again.
        std::vector<std::unique_ptr<uint8_t[]>> m_SavedReturnBuffers;
        // Save call arguments in case the function reuses the space and overwrites the values for the post hook.
        std::vector<std::unique_ptr<uint8_t[]>> m_SavedCallArguments;
    };
}