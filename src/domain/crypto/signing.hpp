#pragma once

#include <cstdint>
#include <span>

#include "condition.hpp"

using std::convertible_to;
using std::same_as;
using std::size_t;


template<typename T>
concept signing = requires(
    typename T::private_key  priv,
    typename T::public_key   pub,
    typename T::signature    sig,
    std::span<const uint8_t> msg
) {
    typename T::private_key;
    typename T::public_key;
    typename T::signature;

    { T::private_key_size  } -> convertible_to<size_t>;
    { T::public_key_size   } -> convertible_to<size_t>;
    { T::signature_size    } -> convertible_to<size_t>;

    { T::generate_private()  } -> same_as<typename T::private_key>;
    { T::derive_public(priv) } -> same_as<typename T::public_key>;



    { T::sign(priv, msg)       } -> same_as<typename T::signature>;
    { T::verify(pub, msg, sig) } -> condition;

    { T::init_random()       } -> same_as<bool>;
};
