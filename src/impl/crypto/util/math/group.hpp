#pragma once
#include <concepts>
#include <cstdint>
#include "domain/crypto/condition.hpp"


template <typename T, typename S>
concept group = 
				requires(std::remove_cvref_t<T> a, std::remove_cvref_t<T> b) {
					{ a + b } -> std::same_as<T>;
					{ a - b } -> std::same_as<T>;
					{ -a } -> std::same_as<T>;
					{ a == b } -> condition;
					{ a != b } -> condition;
					{ T::identity() } -> std::same_as<T>;
					{ T::order } -> std::same_as<uint64_t>;
				};
