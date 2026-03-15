#pragma once
#include "condition.hpp"

template<typename T>
concept ct_comparable = requires(const T a, const T b)
{
    { a == b }      -> condition;
    { a != b }      -> condition;
    { a.is_zero() } -> condition;
};
