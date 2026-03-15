#pragma once
#include <concepts>
#include "Choice.hpp"

template<typename T>
concept CtComparable = requires(T a, T b)
{
    { a == b }      -> std::same_as<Choice>;
    { a != b }      -> std::same_as<Choice>;
    { a.is_zero() } -> std::same_as<Choice>;
};