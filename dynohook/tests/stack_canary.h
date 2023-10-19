namespace dyno {
	class StackCanary {
	public:
		StackCanary();
		~StackCanary() noexcept(false);

        bool isStackGood();
		
	private:
		uint8_t buf[100];
	};
}