#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "impl/crypto/util/choice.hpp"

using std::size_t;
using std::array;

template<typename T, size_t N>
inline array<T, N> ct_select(array<T, N> a, array<T, N> b, choice c)
{
    array<T, N> ret{};
    T mask = static_cast<T>(c.mask());
    for (size_t i = 0; i < N; ++i)
        ret[i] = (a[i] & mask) | (b[i] & ~mask);
    return ret;
}

template<typename T, size_t N>
inline void ct_swap(array<T, N> &a, array<T, N> &b, choice c)
{
    T mask = static_cast<T>(c.mask());
    for (size_t i = 0; i < N; ++i)
    {
        T diff = mask & (a[i] ^ b[i]);
        a[i] ^= diff;
        b[i] ^= diff;
    }
}
