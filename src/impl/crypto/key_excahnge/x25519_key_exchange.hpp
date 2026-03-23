#pragma once

#include <array>
#include <cstdint>
#include <sodium.h>

#include "domain/crypto/key_exchange.hpp"
#include "impl/crypto/util/ct_array.hpp"
#include "impl/crypto/util/ct_optional.hpp"
#include "impl/crypto/util/math/group/montgomery_point.hpp"

class x25519_key_exchange
{
public:
    using private_key   = std::array<uint8_t, 32>;
    using public_key    = std::array<uint8_t, 32>;
    using shared_secret = std::array<uint8_t, 32>;

    static constexpr std::size_t public_key_size    = 32;
    static constexpr std::size_t shared_secret_size = 32;

    static bool init_random() { return sodium_init() != -1; }

    static private_key generate()
    {
        private_key sk;
        randombytes_buf(sk.data(), sk.size());
        return sk;
    }

    static public_key derive_public(const private_key &sk)
    {
        return (montgomery_point::base_point() * scalar_25519::from_bytes(sk))
            .to_affine().to_bytes();
    }

    static ct_optional<shared_secret> exchange(const private_key &sk, const public_key &pk)
    {
        auto point  = montgomery_point::from_affine(field_25519::from_bytes(pk).value_or(field_25519::zero()));
        auto result = (point * scalar_25519::from_bytes(sk)).to_affine();
        return ct_optional<shared_secret>::from_choice(result.to_bytes(), !result.is_zero());
    }
};

static_assert(key_exchange<x25519_key_exchange>);
