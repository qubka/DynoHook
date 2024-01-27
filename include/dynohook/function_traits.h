#pragma once

#include "convention.h"
#include <type_traits>

namespace dyno {
	template<typename F>
	DataObject GetReturn(F func) {
		using trait = FunctionTrait<decltype(func)>;
		return GetType<typename trait::return_type>();
	}

	template <typename F>
	std::vector<DataObject> GetArguments(F func) {
		using trait = FunctionTrait<decltype(func)>;
		std::vector<DataObject> out;
		if constexpr (std::is_member_function_pointer<decltype(func)>::value) {
			out.reserve(trait::arity + 1);
			out.emplace_back(DataType::Pointer);
		} else {
			out.reserve(trait::arity);
		}
		[&]<std::size_t... Is>(std::index_sequence<Is...>) {
			(out.emplace_back(GetType<typename trait::template arg<Is>::type>()), ...);
		}(std::make_index_sequence<trait::arity>{});
		return out;
	}

	template <typename T>
	DataObject GetReturn() {
		return GetType<T>();
	}

	template <typename F>
	std::vector<DataObject> GetArguments() {
		std::vector<DataObject> out;
		using trait = FunctionTrait<F>;
		if constexpr (std::is_member_function_pointer<F>::value) {
			out.reserve(trait::arity + 1);
			out.emplace_back(DataType::Pointer);
		} else {
			out.reserve(trait::arity);
		}
		[&]<std::size_t... Is>(std::index_sequence<Is...>) {
			(out.emplace_back(GetType<typename trait::template arg<Is>::type>()), ...);
		}(std::make_index_sequence<trait::arity>{});
		return out;
	}

	template<typename T>
	DataType GetType() {
		if constexpr (std::is_same_v<T, void>) return DataType::Void;
		if constexpr (std::is_same_v<T, bool>) return DataType::Bool;
		else if constexpr (std::is_same_v<T, int8_t>) return DataType::Int8;
		else if constexpr (std::is_same_v<T, uint8_t>) return DataType::UInt8;
		else if constexpr (std::is_same_v<T, int16_t>) return DataType::Int16;
		else if constexpr (std::is_same_v<T, uint16_t>) return DataType::UInt16;
		else if constexpr (std::is_same_v<T, int32_t>) return DataType::Int32;
		else if constexpr (std::is_same_v<T, uint32_t>) return DataType::UInt32;
		else if constexpr (std::is_same_v<T, int64_t>) return DataType::Int64;
		else if constexpr (std::is_same_v<T, uint64_t>) return DataType::UInt64;
		else if constexpr (std::is_same_v<T, float>) return DataType::Float;
		else if constexpr (std::is_same_v<T, double>) return DataType::Double;
		else if constexpr (std::is_same_v<T, const char*>) return DataType::String;
		else if constexpr (std::is_same_v<T, const wchar_t*>) return DataType:: WString;
		else if constexpr (std::is_pointer<T>::value) return DataType::Pointer;
		else static_assert("Unsupported type");
	}

	template <typename Function>
	struct FunctionTrait;

	template <typename Ret, typename... Args>
	struct FunctionTrait<Ret(*)(Args...)> {
		using return_type = Ret;
		using argument_types = std::tuple<Args...>;
		static constexpr size_t arity = sizeof...(Args);

		template <size_t N>
		struct arg {
			using type = typename std::tuple_element<N, argument_types>::type;
		};
	};

	template <typename Class, typename Ret, typename... Args>
	struct FunctionTrait<Ret(Class::*)(Args...)> {
		using return_type = Ret;
		using argument_types = std::tuple<Args...>;
		static constexpr size_t arity = sizeof...(Args);

		template <size_t N>
		struct arg {
			using type = typename std::tuple_element<N, argument_types>::type;
		};
	};

	template <typename Ret, typename... Args>
	struct FunctionTrait<Ret(Args...)> {
		using return_type = Ret;
		using argument_types = std::tuple<Args...>;
		static constexpr size_t arity = sizeof...(Args);

		template <size_t N>
		struct arg {
			using type = typename std::tuple_element<N, argument_types>::type;
		};
	};
}