#pragma once
#include <concepts>
#include <array>
#include <cstdint>
#include "CtOptional.hpp"

template<typename T>
concept CtSerializable = requires(T a, std::array<uint8_t, T::byte_size>       bytes,
                                       std::array<uint8_t, T::wide_byte_size>  wide_bytes)
{
    { std::integral_constant<std::size_t, T::byte_size>{}      };
    { std::integral_constant<std::size_t, T::wide_byte_size>{}  };
    { std::integral_constant<std::size_t, T::wide_byte_size == 2 * T::byte_size>{} };
    { T::from_bytes(bytes)              } -> std::same_as<CtOptional<T>>;
    { T::from_uniform_bytes(wide_bytes) } -> std::same_as<T>;
    { a.to_bytes()                      } -> std::same_as<decltype(bytes)>;
};