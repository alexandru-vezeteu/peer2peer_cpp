#pragma once
#include "condition.hpp"

template<typename T>
concept ct_comparable = requires( 
    std::remove_cvref_t<T> a,
    std::remove_cvref_t<T> b)
{
    { a == b }      -> condition;
    { a != b }      -> condition;
    { a.is_zero() } -> condition;
};
