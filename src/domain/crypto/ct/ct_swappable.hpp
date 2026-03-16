#pragma once
#include <concepts>
#include "condition.hpp"

template<typename T, typename R>
concept ct_swappable = condition<R> && requires(
    std::remove_cvref_t<T> a,
    std::remove_cvref_t<T> b,
    R c)
{
    { std::remove_cvref_t<T>::ct_swap(a, b, c) };
    { std::remove_cvref_t<T>::ct_swap(a, b) };

};