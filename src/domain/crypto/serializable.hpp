#pragma once
#include <cstdint>
#include <concepts>
#include <array>
#include "domain/crypto/optional.hpp"

using std::integral_constant;
using std::same_as;
using std::size_t;
using std::remove_cvref_t;
using std::array;



template<typename T>
concept serializable = requires(remove_cvref_t<T> a, array<uint8_t, T::byte_size> bytes)
{
    { integral_constant<size_t, T::byte_size>{} };
    { T::from_bytes(bytes) } -> optional;
    { a.to_bytes()         } -> same_as<decltype(bytes)>;
};
