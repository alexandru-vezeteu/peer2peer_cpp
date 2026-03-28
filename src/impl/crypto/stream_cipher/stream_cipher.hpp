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

// RFC 5116 §3: encrypt(K, N, A, P) → C  /  decrypt(K, N, A, C) → P | FAIL
// The nonce N is a first-class, separate input to both operations.
// It is NOT embedded in the ciphertext — the caller/transport layer owns it.
template<typename T>
concept stream_cipher = requires(
    array<uint8_t, T::key_size>         key,
    span<const uint8_t, T::nonce_size>  nonce,
    span<uint8_t>                       buffer,
    span<const uint8_t>                 ciphertext
    ) 
{
    { T::key_size }                          -> convertible_to<size_t>;
    { T::nonce_size }                        -> convertible_to<size_t>;

    { T::encrypt(key, nonce, buffer) }       -> same_as<vector<uint8_t>>;
    { T::decrypt(key, nonce, ciphertext) }   -> same_as<vector<uint8_t>>;
};
