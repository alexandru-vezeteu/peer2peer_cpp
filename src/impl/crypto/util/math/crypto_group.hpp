#pragma once

#include "impl/crypto/util/constant_time.hpp"
#include "impl/crypto/util/math/group.hpp"
#include "domain/crypto/optional.hpp"

template <typename T, typename O, typename C, typename S>
concept crypto_group =
    optional<O> && group<T, S> && constant_time<T, C> && requires(const T a) {
      { a.is_identity() } -> std::same_as<C>;
    };
