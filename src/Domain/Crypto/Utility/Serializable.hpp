#pragma once
#include <cstdint>
#include <concepts>
#include <array>
#include <optional>

template<typename T>
concept Serializable = requires(T a, std::array<uint8_t, T::byte_size> bytes)
{
    { std::integral_constant<std::size_t, T::byte_size>{} };
    { T::from_bytes(bytes) } -> std::same_as<std::optional<T>>;
    { a.to_bytes()         } -> std::same_as<decltype(bytes)>;
};
