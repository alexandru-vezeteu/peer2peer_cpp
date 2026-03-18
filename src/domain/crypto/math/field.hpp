#pragma once
#include <concepts>
#include "domain/crypto/ct/optional.hpp"
#include "domain/crypto/ct/condition.hpp"

template<typename T, typename O>
concept field = optional<O> && requires(std::remove_cvref_t<T> a, std::remove_cvref_t<T> b, std::remove_cvref_t<T> mut)
{
    
    { a + b }      -> std::same_as<T>;
    { a - b }      -> std::same_as<T>;
    { a * b }      -> std::same_as<T>;
    { -a }         -> std::same_as<T>;
    { a.square() } -> std::same_as<T>;
    { a.invert() } -> std::same_as<T>;
    { a == b }     -> condition;
    { T::zero() }  -> std::same_as<T>;
    { T::one()  }  -> std::same_as<T>;
    { T::p() } -> std::same_as<T>;
    


};

template<typename T>
requires field<T, decltype(std::declval<T>().sqrt())>
[[nodiscard]] T operator/(const T& a, const T& b) noexcept {
    return a * b.invert();
}
