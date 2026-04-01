#pragma once

#include <array>
#include <cstdint>
#include <span>

using std::remove_cvref_t;
using std::span;
using std::size_t;
using std::convertible_to;
using std::same_as;
using std::array;

template<typename T>
concept hasher = requires( remove_cvref_t<T> h, span<const uint8_t> data)
{
    { T::digest_size } -> convertible_to<size_t>;

    { h.update(data) } -> same_as<void>;

    { h.finalize() } -> same_as<array<uint8_t, T::digest_size>>;

    { T::hash(data) } -> same_as<array<uint8_t, T::digest_size>>;
};
