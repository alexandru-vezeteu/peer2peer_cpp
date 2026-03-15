#pragma once
#include <concepts>
#include <optional>
// inspo: https://doc.dalek.rs/subtle/




template<typename T>
concept Field = requires(T a, T b)
{
	{ std::integral_constant<std::size_t, T::characteristic_bits>{} };
    { a + b }      -> std::same_as<T>;
    { a - b }      -> std::same_as<T>;
    { a * b }      -> std::same_as<T>;
    { -a }         -> std::same_as<T>;
    { a.square() } -> std::same_as<T>;
    { a.invert() } -> std::same_as<T>;
    { a == b }     -> std::convertible_to<bool>;
    { T::zero() }  -> std::same_as<T>;
    { T::one()  }  -> std::same_as<T>;
    { a.sqrt()  }  -> std::same_as<std::optional<T>>;
};

template<Field T>
[[nodiscard]] T operator/(const T& a, const T& b) noexcept
{
	return a * b.invert();
}