// https://stackoverflow.com/questions/34397819/using-stdfunction-and-stdbind-to-store-callback-and-handle-object-deletion/34400239#34400239

namespace dyno {
	using token = std::shared_ptr<void>;

	template<class...Args>
	class Listener {
		using target = std::function<void(Args...)>;
		using wp_target = std::weak_ptr<target>;
		using sp_target = std::shared_ptr<target>;
		
		static sp_target wrap_target(target t) {
			return std::make_shared<target>(std::move(t));
		};

	public:
		token connect(target f) {
			auto t = wrap_target(std::move(f));
			m_targets.push_back(t);
			return t;
		}
		
		void notify(Args... args) {
			m_targets.erase(
				std::remove_if(m_targets.begin(), m_targets.end(),
					[&](wp_target t) -> bool { return t.expired(); }
				),
				m_targets.end()
			);
			auto targets_copy = m_targets; // in case targets is modified by listeners
			for (auto wp : targets_copy) {
				if (auto sp = wp.lock()) {
					(*sp)(args...);
				}
			}
		}
		
	private:
		std::vector<wp_target> m_targets;
	};
}