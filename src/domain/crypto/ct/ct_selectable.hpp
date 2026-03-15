#pragma once
#include <concepts>
#include "condition.hpp"

template<typename T, class R>
concept ct_selectable = condition<R> && requires(const T a, const T b, R c)
{
    { T::ct_select(a, b, c) } -> std::same_as<T>;
};
