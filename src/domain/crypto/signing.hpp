#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "condition.hpp"

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

    { T::private_key_size  } -> std::convertible_to<std::size_t>;
    { T::public_key_size   } -> std::convertible_to<std::size_t>;
    { T::signature_size    } -> std::convertible_to<std::size_t>;

    { T::generate_private()  } -> std::same_as<typename T::private_key>;
    { T::derive_public(priv) } -> std::same_as<typename T::public_key>;



    { T::sign(priv, msg)       } -> std::same_as<typename T::signature>;
    { T::verify(pub, msg, sig) } -> condition;

    { T::init_random()       } -> std::same_as<bool>;
};
