#pragma once


#include <array>
#include <span>
using std::array;
using std::span;
#include <sodium.h>

#include "domain/crypto/signing.hpp"
#include "domain/crypto/hash.hpp"

#include "impl/crypto/util/choice.hpp"
#include "impl/crypto/hash/sha512.hpp"



template<hasher H>
class eddsa
{
    public:
    static constexpr size_t private_key_size = 32;
    static constexpr size_t public_key_size = 32;
    static constexpr size_t signature_size = 64;

    using private_key = array<uint8_t, private_key_size>;
    using public_key = array<uint8_t, public_key_size>;
    using signature = array<uint8_t, signature_size>;


    static bool init_random()
    {
        return sodium_init() != -1;
    }

    static private_key generate_private()
    {
        private_key seed;
        randombytes_buf(seed.data(), seed.size());
        return seed;
    }
    static public_key derive_public(private_key priv);

    static signature sign(private_key priv, span<const uint8_t> msg);
    static choice verify(public_key pub, span<const uint8_t> msg, signature sig);


};

static_assert(signing<eddsa<SHA512>>);