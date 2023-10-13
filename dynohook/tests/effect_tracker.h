namespace dyno {
	class Effect {
	public:
		Effect();
		void trigger();

		bool didExecute(size_t n);
		
	private:
		uint32_t m_executed;
		uint32_t m_uid;

		inline static std::atomic_uint32_t s_counter = { 0 };
	};

	/**Track if some side effect happened.**/
	class EffectTracker {
	public:
		void push();
		Effect pop();
		Effect& peak();
		
	private:
		std::vector<Effect> m_queue;
	};
}