#pragma once
#include <concepts>
#include "condition.hpp"

template<typename T, class R>
concept ct_selectable = condition<R> && requires(
    std::remove_cvref_t<T> a,
    std::remove_cvref_t<T> b,
    std::remove_cvref_t<R> c)
{
    { T::ct_select(a, b, c) } -> std::same_as<decltype(a)>;
};
