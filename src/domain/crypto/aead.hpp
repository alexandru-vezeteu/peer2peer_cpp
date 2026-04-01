#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

using std::array;
using std::same_as;
using std::size_t;
using std::span;
using std::convertible_to;
using std::vector;

// RFC 5116 AEAD concept
template<typename T>
concept aead = requires(
    array<uint8_t, T::key_size>        key,
    span<const uint8_t, T::nonce_size> nonce,
    span<uint8_t>                      plaintext,
    span<const uint8_t>                blob,
    span<const uint8_t>                aad
)
{
    { T::key_size }   -> convertible_to<size_t>;
    { T::nonce_size } -> convertible_to<size_t>;
    { T::tag_size }   -> convertible_to<size_t>;

    { T::seal(key, nonce, plaintext, aad) } -> same_as<vector<uint8_t>>;
    { T::open(key, nonce, blob, aad) }      -> same_as<vector<uint8_t>>;
};