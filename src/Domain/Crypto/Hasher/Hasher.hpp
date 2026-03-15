#pragma once

#include <array>
#include <cstdint>
#include <span>


template <typename T>
concept Hasher = requires(T h, std::span<const uint8_t> data) 
{
    { T::digest_size } -> std::convertible_to<std::size_t>;

    { h.update(data) } -> std::same_as<void>;

    { h.finalize() } -> std::same_as<std::array<uint8_t, T::digest_size>>;

    { T::hash(data) } -> std::same_as<std::array<uint8_t, T::digest_size>>;
};



