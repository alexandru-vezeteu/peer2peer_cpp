#pragma once
#include <concepts>
#include "domain/crypto/condition.hpp"
using std::remove_cvref_t;
using std::same_as;
template<typename T, class R>
concept ct_selectable = condition<R> && requires(
    remove_cvref_t<T> a,
    remove_cvref_t<T> b,
    remove_cvref_t<R> c)
{
    { ct_select(a, b, c) } -> same_as<decltype(a)>;
};
