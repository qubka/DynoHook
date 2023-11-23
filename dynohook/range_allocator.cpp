#include "range_allocator.h"
#include "fb_allocator.h"

using namespace dyno;

RangeAllocator::RangeAllocator(uint8_t blockSize, uint8_t blockCount) : m_maxBlocks{blockCount}, m_blockSize{blockSize} {
}

std::shared_ptr<FBAllocator> RangeAllocator::findOrInsertAllocator(uintptr_t min, uintptr_t max) {
    for (const auto& allocator : m_allocators) {
        if (allocator->inRange(min) && allocator->inRange(max - 1))
            return allocator;
    }

    auto allocator = std::make_shared<FBAllocator>(min, max, m_blockSize, m_maxBlocks);
    if (!allocator->initialize())
        return nullptr;

    m_allocators.push_back(allocator);
    return allocator;
}

char* RangeAllocator::allocate(uintptr_t min, uintptr_t max) {
#if DYNO_ARCH_X86 == 32
    if (max > 0x7FFFFFFF) {
        max = 0x7FFFFFFF; // allocator apis fail in 32bit above this range
    }
#endif

    std::lock_guard<std::mutex> m_lock{m_mutex};
    auto allocator = findOrInsertAllocator(min, max);
    if (!allocator)
        return nullptr;

    char* addr = allocator->allocate();
    m_allocMap[(uintptr_t)addr] = allocator;
    return addr;
}

void RangeAllocator::deallocate(uintptr_t addr) {
    std::lock_guard<std::mutex> m_lock{m_mutex};
    if (auto it = m_allocMap.find(addr); it != m_allocMap.end()) {
        auto allocator = it->second;
        allocator->deallocate((char*)addr);
        m_allocMap.erase(addr);

        // this instance + instance in m_allocators array
        if (allocator.use_count() == 2) {
            m_allocators.erase(std::remove(m_allocators.begin(), m_allocators.end(), allocator), m_allocators.end());
        }
    } else {
        assert(false);
    }
}