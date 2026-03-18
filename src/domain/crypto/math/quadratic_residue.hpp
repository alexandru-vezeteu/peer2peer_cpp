#pragma once
#include <concepts>
#include "domain/crypto/ct/optional.hpp"

template<typename T, typename O>
concept quadratic_residue = optional<O> and requires(const T a)
{
    { sqrt(a)  }  -> std::same_as<O>;
    { T::i() }->std::same_as<T>;
};