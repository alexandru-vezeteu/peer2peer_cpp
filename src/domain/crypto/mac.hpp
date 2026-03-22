#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "condition.hpp"

template<typename T>
concept mac = requires(
    std::span<const uint8_t> key,
    std::span<const uint8_t> msg,
    std::span<const uint8_t> tag
) {
    { T::key_size } -> std::convertible_to<std::size_t>;
    { T::tag_size } -> std::convertible_to<std::size_t>;

    { T::generate(key, msg)    } -> std::same_as<std::array<uint8_t, T::tag_size>>;
    { T::verify(key, msg, tag) } -> condition;
};
