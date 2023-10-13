#include "fb_allocator.h"

void* ALLOC_NewBlock(ALLOC_Allocator* self)  {
    ALLOC_Block* pBlock = NULL;

    // If we have not exceeded the pool maximum
    if (self->poolIndex < self->maxBlocks) {
        // Get pointer to a new fixed memory block within the pool
        pBlock = (ALLOC_Block*)(self->pPool + (self->poolIndex++ * self->blockSize));
    }

    return pBlock;
} 

void ALLOC_Push(ALLOC_Allocator* self, void* pBlock) {
    if (!pBlock)
        return;

    // Get a pointer to the client's location within the block
    ALLOC_Block* pClient = (ALLOC_Block*)pBlock;

    // Point client block's next pointer to head
    pClient->pNext = self->pHead;

    // The client block is now the new head
    self->pHead = pClient;
}

void* ALLOC_Pop(ALLOC_Allocator* self) {
    ALLOC_Block* pBlock = NULL;

    // Is the free-list empty?
    if (self->pHead) {
        // Remove the head block
        pBlock = self->pHead;

        // Set the head to the next block
        self->pHead = (ALLOC_Block*)self->pHead->pNext;
    }
 
    return pBlock;
} 

void* ALLOC_Alloc(ALLOC_HANDLE hAlloc, size_t size) {
    ALLOC_Allocator* self = NULL;
    void* pBlock = NULL;

    assert(hAlloc);

    // Convert handle to an ALLOC_Allocator instance
    self = (ALLOC_Allocator*)hAlloc;

    // Ensure requested size fits within memory block (size);
    assert(size <= self->blockSize);

    // Get a block from the free-list
    pBlock = ALLOC_Pop(self);

    // If the free-list empty?
    if (!pBlock) {
        // Get a new block from the pool
        pBlock = ALLOC_NewBlock(self);
    }

    if (pBlock) {
        // Keep track of usage statistics
        self->allocations++;
        self->blocksInUse++;
        if (self->blocksInUse > self->maxBlocksInUse)
            self->maxBlocksInUse = self->blocksInUse;
    } 
    return pBlock;
} 

void* ALLOC_Calloc(ALLOC_HANDLE hAlloc, size_t num, size_t size) {
    void* pMem = NULL;
    size_t n = 0;

    assert(hAlloc);

    // Compute the total size of the block
    n = num * size;

    // Allocate the memory
    pMem = ALLOC_Alloc(hAlloc, n);

    if (pMem) {
        memset(pMem, 0, n);
    }
    return pMem;
}

void ALLOC_Free(ALLOC_HANDLE hAlloc, void* pBlock) {
    ALLOC_Allocator* self = NULL;

    if (!pBlock)
        return;

    assert(hAlloc);

    // Cast handle to an allocator instance
    self = (ALLOC_Allocator*)hAlloc;

    // Push the block onto a stack (i.e. the free-list)
    ALLOC_Push(self, pBlock);

    // Keep track of usage statistics
    self->deallocations++;
    self->blocksInUse--;
}

using namespace dyno; 

FBAllocator::FBAllocator(uintptr_t min, uintptr_t max, uint8_t blockSize, uint8_t blockCount) :
	m_allocator{nullptr}, 
	m_hAllocator{nullptr},
	m_min{min},
	m_max{max},
	m_dataPool{0},
	m_maxBlocks{blockCount},
	m_usedBlocks{0},
	m_blockSize{blockSize},
	m_alloc2Supported{boundedAllocSupported()} {
}

FBAllocator::~FBAllocator() {
	size_t freeSize = 0;

	if (m_allocator) {
		freeSize = m_allocator->blockSize * m_allocator->maxBlocks;
		delete m_allocator;
		m_allocator = nullptr;
		m_hAllocator = nullptr;
	}

	if(m_dataPool) { 
		boundAllocFree(m_dataPool, freeSize);
		m_dataPool = 0;
	}
}

bool FBAllocator::initialize() {
	size_t alignment = getAllocationAlignment();
    uintptr_t start = AlignUpwards(m_min, alignment);
    uintptr_t end = AlignDownwards(m_max, alignment);
	
	if (m_alloc2Supported) {
		// alignment shrinks area by aligning both towards middle so we don't allocate beyond the given bounds
		m_dataPool = boundAlloc(start, end, ALLOC_BLOCK_SIZE(m_blockSize) * m_maxBlocks);
		if (!m_dataPool)
			return false;
	} else {
		m_dataPool = boundAllocLegacy(start, end, ALLOC_BLOCK_SIZE(m_blockSize) * m_maxBlocks);
		if (!m_dataPool)
			return false;
	}
	
    m_allocator = new ALLOC_Allocator{"dyno", (char*)m_dataPool, 
		m_blockSize, ALLOC_BLOCK_SIZE(m_blockSize), m_maxBlocks, nullptr, 0, 0, 0, 0, 0};

    m_hAllocator = m_allocator;
	return true;
}

char* FBAllocator::allocate() {
	if (m_usedBlocks + 1 == m_maxBlocks)
		return nullptr;

	m_usedBlocks++;
	return (char*)ALLOC_Alloc(m_hAllocator, m_blockSize);
}

char* FBAllocator::callocate(uint8_t num) {
	m_usedBlocks += num;
	return (char*)ALLOC_Calloc(m_hAllocator, num, m_blockSize);
}

void FBAllocator::deallocate(char* mem) {
	m_usedBlocks--;
	ALLOC_Free(m_hAllocator, mem);
}

bool FBAllocator::inRange(uintptr_t addr) const {
	if (addr >= m_min && addr < m_max)
		return true;
	return false;
}

bool FBAllocator::intersectsRange(uintptr_t min, uintptr_t max) const {
    uintptr_t _min = std::max(m_min, min);
    uintptr_t _max = std::min(m_max, max);
	if (_min <= _max)
		return true;
	return false;
}

uint8_t FBAllocator::intersectionLoadFactor(uintptr_t min, uintptr_t max) const {
	assert(intersectsRange(min, max));
    uintptr_t _min = std::max(m_min, min);
    uintptr_t _max = std::min(m_max, max);
	double intersectLength = (double)(_max - _min);
	return (uint8_t)((intersectLength / (double)(max - min)) * 100.0);
}
