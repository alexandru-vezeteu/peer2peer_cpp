#pragma once
#include <concepts>
#include "ct/optional.hpp"
#include "ct/condition.hpp"

template<typename T, typename O>
concept field = optional<O> && requires(const T a, const T b, T mut)
{
    { std::integral_constant<std::size_t, T::characteristic_bits>{} };
    { a + b }      -> std::same_as<T>;
    { a - b }      -> std::same_as<T>;
    { a * b }      -> std::same_as<T>;
    { -a }         -> std::same_as<T>;
    { a.square() } -> std::same_as<T>;
    { a.invert() } -> std::same_as<T>;
    { a == b }     -> condition;
    { T::zero() }  -> std::same_as<T>;
    { T::one()  }  -> std::same_as<T>;
    {T::p()} -> std::same_as<T>;
    { a.sqrt()  }  -> std::same_as<O>;

    { mut.reduce_inplace() };
    { a.reduce() } ->std::same_as<T>;
};

template<typename T>
requires field<T, decltype(std::declval<T>().sqrt())>
[[nodiscard]] T operator/(const T& a, const T& b) noexcept {
    return a * b.invert();
}
