#pragma once
#include <concepts>
#include <array>
#include <cstdint>
#include "optional.hpp"

template<typename T>
concept ct_serializable = requires(
        std::remove_cvref_t<T> a,
        const std::array<uint8_t, T::byte_size>      bytes,
        const std::array<uint8_t, T::wide_byte_size> wide_bytes)
{
    { std::integral_constant<std::size_t, T::byte_size>{}      };
    { std::integral_constant<std::size_t, T::wide_byte_size>{}  };
    { T::from_bytes(bytes)              } -> optional_of<T>;
    { T::from_uniform_bytes(wide_bytes) } -> std::same_as<T>;
    { a.to_bytes()                      } -> std::same_as<decltype(bytes)>;
};
