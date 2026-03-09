#include <algorithm>
#include <fstream>
#include <iostream>
#include <print>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include "../Crypto/Hasher/sha256.hpp"
#include "../Crypto/Hasher/sha512.hpp"

static void print_hex(std::span<const uint8_t> data) 
{
    for (uint8_t b : data) 
    {
        std::print("{:02x}", b);
    }
}

static std::vector<uint8_t> openssl_hash(const EVP_MD *md, std::string_view input) 
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());

    std::vector<uint8_t> out(EVP_MD_size(md));
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, out.data(), &len);
    EVP_MD_CTX_free(ctx);
    out.resize(len);
    return out;
}

static int passed = 0;
static int failed = 0;

static bool bytes_equal(std::span<const uint8_t> a, std::span<const uint8_t> b) 
{
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

static void test_sha256(std::string_view label, std::string_view input) 
{
    auto data = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t *>(input.data()),
        input.size()
    );

    auto our = SHA256::hash(data);
    auto ref = openssl_hash(EVP_sha256(), input);

    bool ok = bytes_equal(our, std::span<const uint8_t>(ref));
    std::print("[SHA-256] {}: ", label);

    if (ok) 
    {
        std::println("PASS");
        ++passed;
    } 
    else 
    {
        std::println("FAIL");
        std::print("  Got:      ");
        print_hex(our);
        std::print("\n  Expected: ");
        print_hex(ref);
        std::println("");
        ++failed;
    }
}

static void test_sha512(std::string_view label, std::string_view input) 
{
    auto data = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t *>(input.data()), 
        input.size()
    );

    auto our = SHA512::hash(data);
    auto ref = openssl_hash(EVP_sha512(), input);

    bool ok = bytes_equal(our, std::span<const uint8_t>(ref));
    std::print("[SHA-512] {}: ", label);

    if (ok) 
    {
        std::println("PASS");
        ++passed;
    } 
    else 
    {
        std::println("FAIL");
        std::print("  Got:      ");
        print_hex(our);
        
        std::print("\n  Expected: ");
        print_hex(ref);
        
        std::println("");
        ++failed;
    }
}

static void test_file_sha256(std::string_view label, std::string_view path)
{
    std::ifstream file(path.data(), std::ios::binary);
    if (!file) 
    {
        std::println("[SHA-256] {}: SKIP (File not found: {})", label, path);
        return;
    }

    SHA256 our_hasher;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    std::vector<uint8_t> buffer(16384); // 16KB chunks
    while (file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) or
            file.gcount() > 0) 
    {
        size_t bytes_read = static_cast<size_t>(file.gcount());
        std::span<const uint8_t> chunk{buffer.data(), bytes_read};

        our_hasher.update(chunk);
        EVP_DigestUpdate(ctx, chunk.data(), chunk.size());
    }

    auto our_digest = our_hasher.finalize();
    std::vector<uint8_t> ref_digest(EVP_MD_size(EVP_sha256()));
    unsigned int ref_len = 0;
    EVP_DigestFinal_ex(ctx, ref_digest.data(), &ref_len);
    EVP_MD_CTX_free(ctx);

    bool ok = bytes_equal(our_digest,
                        std::span<const uint8_t>(ref_digest.data(), ref_len));

    std::print("[SHA-256] {} ({}): ", label, path);

    if (ok) 
    {
        std::println("PASS");
        ++passed;
    } 
    else 
    {
        std::println("FAIL");
        
        std::print("  Got:      ");
        print_hex(our_digest);
        
        std::print("\n  Expected: ");
        print_hex(ref_digest);
        
        std::println("");
        ++failed;
    }
}

static void test_file_sha512(std::string_view label, std::string_view path)
{
    std::ifstream file(path.data(), std::ios::binary);
    if (!file) 
    {
        std::println("[SHA-512] {}: SKIP (File not found: {})", label, path);
        return;
    }

    SHA512 our_hasher;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr);

    std::vector<uint8_t> buffer(16384); // 16KB chunks
    while (file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) or
            file.gcount() > 0) 
    {
        size_t bytes_read = static_cast<size_t>(file.gcount());
        std::span<const uint8_t> chunk{buffer.data(), bytes_read};

        our_hasher.update(chunk);
        EVP_DigestUpdate(ctx, chunk.data(), chunk.size());
    }

    auto our_digest = our_hasher.finalize();
    std::vector<uint8_t> ref_digest(EVP_MD_size(EVP_sha512()));
    unsigned int ref_len = 0;
    EVP_DigestFinal_ex(ctx, ref_digest.data(), &ref_len);
    EVP_MD_CTX_free(ctx);

    bool ok = bytes_equal(our_digest,
                        std::span<const uint8_t>(ref_digest.data(), ref_len));

    std::print("[SHA-512] {} ({}): ", label, path);

    if (ok) 
    {
        std::println("PASS");
        ++passed;
    } 
    else 
    {
        std::println("FAIL");
        
        std::print("  Got:      ");
        print_hex(our_digest);
        
        std::print("\n  Expected: ");
        print_hex(ref_digest);
        
        std::println("");
        ++failed;
    }
}

int main()
{
    test_sha256("\"abc\"", "abc");
    test_sha256("empty string", "");
    test_sha256("448-bit msg",
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    test_sha256("quick brown fox", "The quick brown fox jumps over the lazy dog");
    test_file_sha256("file1", "../test_files/hash/test1.bin");
    test_file_sha256("file2", "../test_files/hash/test2.bin");


    test_sha512("\"abc\"", "abc");
    test_sha512("empty string", "");
    test_sha512("896-bit msg",
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    test_sha512("quick brown fox", "The quick brown fox jumps over the lazy dog");
    test_file_sha512("file1", "../test_files/hash/test1.bin");
    test_file_sha512("file2", "../test_files/hash/test2.bin");



    std::println("\n{} passed, {} failed.", passed, failed);  
    return failed == 0 ? 0 : 1;
}
