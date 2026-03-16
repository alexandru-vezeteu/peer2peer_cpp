#include <print>
#include <random>
#include <sodium.h>
#include "impl/crypto/field/field_25519.hpp"

static int passed = 0;
static int failed = 0;

#define TEST(label, condition) \
	do { \
		if (condition) { std::println("[PASS] {}", label); ++passed; } \
		else           { std::println("[FAIL] {}", label); ++failed; } \
	} while (0)

#define EQ(a, b)  ((a) == (b)).unwrap_public()
#define NEQ(a, b) ((a) != (b)).unwrap_public()

int main()
{
	if (sodium_init() < 0) return 1;

	std::println("=== field_25519 stress tests ===\n");

	auto zero = field_25519::zero();
	auto one  = field_25519::one();
	auto p    = field_25519::p();

	// --- every value in [p, p+18] must reduce to [0, 18] ---
	for (uint64_t i = 0; i <= 18; ++i) {
		auto label = std::format("(p + {}) == {}", i, i);
		TEST(label, EQ((p + i).reduce(), zero + i));
	}

	// --- add max uint64 then reduce is stable ---
	auto max = std::numeric_limits<uint64_t>::max();
	TEST("(1 + max_u64) reduce stable", EQ((one + max).reduce().reduce(), (one + max).reduce()));

	// --- sub max uint64 then reduce is stable ---
	TEST("(1 - max_u64) reduce stable", EQ((one - max).reduce().reduce(), (one - max).reduce()));

	// --- repeated squaring stays stable: a^(2^20) reduce idempotent ---
	auto a = one + 7u;
	for (int i = 0; i < 20; ++i) a = a.square();
	TEST("a^(2^20) reduce idempotent", EQ(a.reduce(), a.reduce().reduce()));

	// --- inversion holds across a range of values ---
	for (uint64_t v = 1; v <= 50; ++v) {
		auto x = one + (v - 1);
		auto label = std::format("{} * {}^-1 == 1", v, v);
		TEST(label, EQ((x * x.invert()).reduce(), one));
	}

	// --- random fuzz: a*a^-1 == 1 for random values ---
	std::mt19937_64 rng(0xdeadbeef);
	std::uniform_int_distribution<uint64_t> dist(1, (1ULL << 50) - 1);
	for (int i = 0; i < 100; ++i) {
		auto x = one + dist(rng);
		if (!EQ((x * x.invert()).reduce(), one)) {
			std::println("[FAIL] random inversion fuzz (iteration {})", i);
			++failed;
		}
	}
	std::println("[PASS] 100x random inversion fuzz");
	++passed;

	// --- random fuzz: distributivity a*(b+c) == a*b + a*c ---
	for (int i = 0; i < 100; ++i) {
		auto a2 = one + dist(rng);
		auto b  = one + dist(rng);
		auto c  = one + dist(rng);
		if (!EQ((a2 * (b + c)).reduce(), (a2*b + a2*c).reduce())) {
			std::println("[FAIL] distributivity fuzz (iteration {})", i);
			++failed;
			goto done;
		}
	}
	std::println("[PASS] 100x random distributivity fuzz");
	++passed;

done:
	// --- from_uniform_bytes ---
	// All-zeros → 0
	{
		std::array<uint8_t, 64> b{};
		auto r = field_25519::from_uniform_bytes(b);
		TEST("from_uniform(0...0) == 0", EQ(r, zero));
	}
	// {1, 0...} → lo=1, hi=0 → result=1
	{
		std::array<uint8_t, 64> b{};
		b[0] = 1;
		auto r = field_25519::from_uniform_bytes(b);
		TEST("from_uniform({1,0...}) == 1", EQ(r, one));
	}
	// {0...0, 1, 0...} → lo=0, hi=1 → result = 1*19 + 0 = 19
	{
		std::array<uint8_t, 64> b{};
		b[32] = 1;
		auto r = field_25519::from_uniform_bytes(b);
		TEST("from_uniform({0...0,1,0...}) == 19", EQ(r, one + 18u));
	}
	// Result is always in [0, p) — reduce idempotent
	{
		std::array<uint8_t, 64> b;
		randombytes_buf(b.data(), b.size());
		auto r = field_25519::from_uniform_bytes(b);
		TEST("from_uniform random: reduce idempotent", EQ(r, r.reduce()));
	}
	// Two different inputs give different results (with overwhelming probability)
	{
		std::array<uint8_t, 64> b1, b2;
		randombytes_buf(b1.data(), b1.size());
		randombytes_buf(b2.data(), b2.size());
		auto r1 = field_25519::from_uniform_bytes(b1);
		auto r2 = field_25519::from_uniform_bytes(b2);
		TEST("from_uniform: different inputs → different outputs", NEQ(r1, r2));
	}

	std::println("\n{} passed, {} failed", passed, failed);
	return failed == 0 ? 0 : 1;
}
