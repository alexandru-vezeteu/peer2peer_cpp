#pragma once

#include "impl/crypto/util/constant_time.hpp"
#include "impl/crypto/util/math/field.hpp"
#include "domain/crypto/serializable.hpp"

template <typename T, typename O, typename C>
concept crypto_field =
    optional<O> && field<T, O> && constant_time<T, C> && serializable<T> && requires(T a) {
      { std::integral_constant<std::size_t, T::characteristic_bits>{} };
      { a.is_one() } -> std::same_as<C>;
      { a.reduce_inplace() };
      { a.reduce() } -> std::same_as<T>;
    };
