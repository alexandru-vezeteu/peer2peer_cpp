#pragma once

#include <concepts>
#include <cstddef>
#include "domain/crypto/optional.hpp"

using std::convertible_to;
using std::same_as;
using std::size_t;

template<typename T>
concept key_exchange = requires(
    typename T::private_key sk,
    typename T::public_key  pk
) {
    typename T::private_key;
    typename T::public_key;
    typename T::shared_secret;

    { T::public_key_size    } -> convertible_to<size_t>;
    { T::shared_secret_size } -> convertible_to<size_t>;

    { T::init_random()       } -> same_as<bool>;

    { T::generate()          } -> same_as<typename T::private_key>;
    { T::derive_public(sk)   } -> same_as<typename T::public_key>;
    { T::exchange(sk, pk)    } -> optional;
};
