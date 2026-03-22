#pragma once

#include <concepts>
#include <cstddef>

template<typename T>
concept key_exchange = requires(
    typename T::private_key sk,
    typename T::public_key  pk
) {
    typename T::private_key;
    typename T::public_key;
    typename T::shared_secret;

    { T::public_key_size    } -> std::convertible_to<std::size_t>;
    { T::shared_secret_size } -> std::convertible_to<std::size_t>;

    { T::init_random()       } -> std::same_as<bool>;

    { T::generate()          } -> std::same_as<typename T::private_key>;
    { T::derive_public(sk)   } -> std::same_as<typename T::public_key>;
    { T::exchange(sk, pk)    } -> std::same_as<typename T::shared_secret>;
};
