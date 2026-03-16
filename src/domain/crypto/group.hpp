#pragma once
#include <concepts>
#include <cstdint>
#include "ct/condition.hpp"

template<typename T>
concept group = requires(const T a, const T b, const uint64_t k)
{
    { a + b }       -> std::same_as<T>;
    { a - b }       -> std::same_as<T>;
    { -a }          -> std::same_as<T>;
    { a == b }      -> condition;
    { a!=b }        -> condition;
    { a*k }           ->std::same_as<T>;
    { T::identity } -> std::same_as<T>;
    { T::order } -> std::same_as<uint64_t>;

};

