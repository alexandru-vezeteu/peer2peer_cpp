#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "impl/crypto/util/choice.hpp"

template<typename T, std::size_t N>
inline std::array<T, N> ct_select(std::array<T, N> a, std::array<T, N> b, choice c)
{
    std::array<T, N> ret{};
    T mask = static_cast<T>(c.mask());
    for (std::size_t i = 0; i < N; ++i)
        ret[i] = (a[i] & mask) | (b[i] & ~mask);
    return ret;
}

template<typename T, std::size_t N>
inline void ct_swap(std::array<T, N> &a, std::array<T, N> &b, choice c)
{
    T mask = static_cast<T>(c.mask());
    for (std::size_t i = 0; i < N; ++i)
    {
        T diff = mask & (a[i] ^ b[i]);
        a[i] ^= diff;
        b[i] ^= diff;
    }
}
