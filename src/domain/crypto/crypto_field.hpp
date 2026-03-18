#pragma once

#include "math/field.hpp"
#include "ct/constant_time.hpp"
#include "ct/ct_serializable.hpp"

template<typename T, typename O, typename C>
concept crypto_field = optional<O> && field<T, O> && constant_time<T, C> && ct_serializable<T> && requires(T a)
{
    { std::integral_constant<std::size_t, T::characteristic_bits>{} };
    { a.is_one() } -> std::same_as<C>;
    { a.reduce_inplace() };
    { a.reduce() } ->std::same_as<T>;
};
