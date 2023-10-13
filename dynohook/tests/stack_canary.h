namespace dyno {
	class StackCanary {
	public:
		StackCanary();
		bool isStackGood();
		~StackCanary() noexcept(false);
		
	private:
		uint8_t buf[100];
	};
}