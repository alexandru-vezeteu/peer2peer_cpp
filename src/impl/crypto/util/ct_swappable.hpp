#pragma once
#include <concepts>
#include "domain/crypto/condition.hpp"

template<typename T, typename R>
concept ct_swappable = condition<R> && requires(
    std::remove_cvref_t<T> a,
    std::remove_cvref_t<T> b,
    R c)
{
    { ct_swap(a, b, c) };
    { ct_swap(a, b) };
};
