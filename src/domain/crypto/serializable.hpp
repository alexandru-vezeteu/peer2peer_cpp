#pragma once
#include <cstdint>
#include <concepts>
#include <array>
#include "domain/crypto/optional.hpp"

template<typename T>
concept serializable = requires(std::remove_cvref_t<T> a, std::array<uint8_t, T::byte_size> bytes)
{
    { std::integral_constant<std::size_t, T::byte_size>{} };
    { T::from_bytes(bytes) } -> optional;
    { a.to_bytes()         } -> std::same_as<decltype(bytes)>;
};
