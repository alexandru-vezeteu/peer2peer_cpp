#pragma once

#include <array>
#include <cstdint>
#include <sodium.h>

#include "domain/crypto/key_exchange.hpp"
#include "impl/crypto/util/ct_optional.hpp"
#include "impl/crypto/util/ct_array.hpp"


class x25519_libsodium_key_exchange
{
public:
    using private_key   = std::array<uint8_t, crypto_scalarmult_SCALARBYTES>;
    using public_key    = std::array<uint8_t, crypto_scalarmult_BYTES>;
    using shared_secret = std::array<uint8_t, crypto_scalarmult_BYTES>;

    static constexpr std::size_t public_key_size    = crypto_scalarmult_BYTES;
    static constexpr std::size_t shared_secret_size = crypto_scalarmult_BYTES;

    static bool init_random() { return sodium_init() != -1; }

    static private_key generate()
    {
        private_key sk;
        randombytes_buf(sk.data(), sk.size());
        return sk;
    }

    static public_key derive_public(const private_key &sk)
    {
        public_key pk;
        crypto_scalarmult_base(pk.data(), sk.data());
        return pk;
    }

    static ct_optional<shared_secret> exchange(const private_key &sk, const public_key &pk)
    {
        shared_secret ss{};
        [[maybe_unused]] int r = crypto_scalarmult(ss.data(), sk.data(), pk.data());
        uint64_t acc = 0;
        for (auto b : ss) acc |= b;
        return ct_optional<shared_secret>::from_choice(ss, choice::from_nonzero(acc));
    }
};

static_assert(key_exchange<x25519_libsodium_key_exchange>);
