namespace dyno {
    class FBAllocator;
	class RangeAllocator {
	public:
		RangeAllocator(uint8_t blockSize, uint8_t blockCount);
		~RangeAllocator() = default;
		NONCOPYABLE(RangeAllocator);

		char* allocate(uint64_t min, uint64_t max);
		void deallocate(uint64_t addr);
		
	private:
		std::shared_ptr<FBAllocator> findOrInsertAllocator(uint64_t min, uint64_t max);

		uint8_t m_maxBlocks;
		uint8_t m_blockSize;
		std::mutex m_mutex;
		std::vector<std::shared_ptr<FBAllocator>> m_allocators;
		std::unordered_map<uint64_t, std::shared_ptr<FBAllocator>> m_allocMap;
	};
}