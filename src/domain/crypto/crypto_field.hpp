#pragma once

#include "field.hpp"
#include "ct/constant_time.hpp"
#include "ct/ct_serializable.hpp"

template<typename T, typename O, typename C>
concept crypto_field = optional<O> && field<T, O> && constant_time<T, C> && ct_serializable<T> && requires(T a)
{
    { a.is_one() } -> std::same_as<C>;
    { a.sqrt()   } -> std::same_as<O>;
};
