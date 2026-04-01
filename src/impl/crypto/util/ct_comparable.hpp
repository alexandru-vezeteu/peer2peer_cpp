#pragma once
#include "domain/crypto/condition.hpp"
using std::remove_cvref_t;
template<typename T>
concept ct_comparable = requires(
    remove_cvref_t<T> a,
    remove_cvref_t<T> b)
{
    { a == b }      -> condition;
    { a != b }      -> condition;
    { a.is_zero() } -> condition;
};
