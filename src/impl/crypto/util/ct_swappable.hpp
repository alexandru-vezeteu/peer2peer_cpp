#pragma once

#include "domain/crypto/condition.hpp"

using std::remove_cvref_t; 

template<typename T, typename R>
concept ct_swappable = condition<R> && 
requires
(
    remove_cvref_t<T> a,
    remove_cvref_t<T> b,
    R c
)
{
    { ct_swap(a, b, c) };
    { ct_swap(a, b) };
};
