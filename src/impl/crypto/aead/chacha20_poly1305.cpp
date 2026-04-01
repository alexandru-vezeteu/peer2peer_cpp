#include "chacha20_poly1305.hpp"

namespace crypto {

vector<uint8_t> chacha20_poly1305::seal(
        array<uint8_t, key_size>         key,
        span<const uint8_t, nonce_size>  nonce,
        span<uint8_t>                    plaintext,
        span<const uint8_t>              aad
    )
{
    
    auto auth_key = chacha_20::subkey(key, nonce);
    auto ciphertext = chacha_20::encrypt(key, nonce, plaintext);
    auto mac_input = build_mac_input(aad, ciphertext);
    auto tag = poly_1305::generate(auth_key, mac_input);
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}


vector<uint8_t> chacha20_poly1305::open(
        array<uint8_t, key_size>         key,
        span<const uint8_t, nonce_size>  nonce,
        span<const uint8_t>              blob,
        span<const uint8_t>              aad
    )
{
    if (blob.size() < tag_size)
        return {};

    span<const uint8_t> ciphertext{ blob.data(), blob.size() - tag_size };
    span<const uint8_t> tag       { blob.data() + ciphertext.size(), tag_size };

    auto auth_key = chacha_20::subkey(key, nonce);

    auto mac_input = build_mac_input(aad, ciphertext);
    if (!poly_1305::verify(auth_key, mac_input, tag))
        return {};
    return chacha_20::decrypt(key, nonce, ciphertext);
}

vector<uint8_t> chacha20_poly1305::build_mac_input(
        span<const uint8_t> aad,
        span<const uint8_t> ciphertext
    )
{
    vector<uint8_t> out;
    out.reserve(aad.size() + 16 + ciphertext.size() + 16 + 16);

    auto append_padded = [&](span<const uint8_t> data)
    {
        out.insert(out.end(), data.begin(), data.end());
        size_t pad = (16 - data.size() % 16) % 16;
        out.insert(out.end(), pad, 0x00);
    };

    auto append_le64 = [&](uint64_t v) 
    {
        for (int i = 0; i < 8; ++i)
            out.push_back(uint8_t(v >> (8 * i)));
    };

    append_padded(aad);
    append_padded(ciphertext);
    append_le64(aad.size());
    append_le64(ciphertext.size());
    return out;
}

} // namespace crypto
