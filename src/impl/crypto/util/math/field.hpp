#pragma once
#include "domain/crypto/condition.hpp"
#include "domain/crypto/optional.hpp"
#include <concepts>

template <typename T, typename O>
concept field =
	optional<O> && requires(std::remove_cvref_t<T> a, std::remove_cvref_t<T> b,
							std::remove_cvref_t<T> mut) {
		{ a + b } -> std::same_as<T>;
		{ a - b } -> std::same_as<T>;
		{ a * b } -> std::same_as<T>;
		{ -a } -> std::same_as<T>;
		{ a.square() } -> std::same_as<T>;
		{ a.invert() } -> std::same_as<T>;
		{ a == b } -> condition;
		{ T::zero() } -> std::same_as<T>;
		{ T::one() } -> std::same_as<T>;
		{ T::p() } -> std::same_as<T>;
	};

//??
template <typename T, typename O>
	requires field<T, O>
[[nodiscard]] T operator/(const T &a, const T &b) noexcept
{
	return a * b.invert();
}
