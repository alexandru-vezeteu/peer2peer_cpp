#pragma once
#include <concepts>
#include "Choice.hpp"
template<typename T>
concept CtSelectable = requires(T a, T b, Choice c)
{
    { T::ct_select(a, b, c) } -> std::same_as<T>;
};