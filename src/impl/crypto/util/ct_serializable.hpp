#pragma once
#include <concepts>
#include <array>
#include <cstdint>
#include "domain/crypto/optional.hpp"
using std::remove_cvref_t;
using std::size_t;
using std::integral_constant;
using std::same_as;
using std::array;

template<typename T>
concept ct_serializable = requires(
        remove_cvref_t<T> a,
        const array<uint8_t, T::byte_size>      bytes,
        const array<uint8_t, T::wide_byte_size> wide_bytes)
{
    { integral_constant<size_t, T::byte_size>{}      };
    { integral_constant<size_t, T::wide_byte_size>{}  };
    { T::from_bytes(bytes)              } -> optional_of<T>;
    { T::from_uniform_bytes(wide_bytes) } -> same_as<T>;
    { a.to_bytes()                      } -> same_as<decltype(bytes)>;
};
