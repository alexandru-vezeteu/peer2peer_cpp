#pragma once

#include "group.hpp"
#include "ct/constant_time.hpp"
#include "ct/ct_serializable.hpp"


template<typename T, typename O, typename C>
concept crypto_group = optional<O> && group<T> && constant_time<T, C> && ct_serializable<T> && requires(const T a)
{
    { a.is_identity() } -> std::same_as<C>;
};
