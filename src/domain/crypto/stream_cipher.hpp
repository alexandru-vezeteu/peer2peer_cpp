#pragma once

#include <cstdint>
#include <span>


template<typename T>
concept stream_cipher = requires(
    std::array<uint8_t, T::key_size> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> input,
    std::span<uint8_t>       output,
    uint64_t                 counter
) {
    { T::key_size   } -> std::convertible_to<std::size_t>;
    { T::nonce_size } -> std::convertible_to<std::size_t>;

    { T::process(key, nonce, counter, input, output) } -> std::same_as<void>;
};
