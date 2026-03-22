#include <print>
#include <sodium.h>
#include "impl/crypto/util/math/field/field_25519.hpp"

static int passed = 0;
static int failed = 0;

#define TEST(label, condition) \
	do { \
		if (condition) { std::println("[PASS] {}", label); ++passed; } \
		else           { std::println("[FAIL] {}", label); ++failed; } \
	} while (0)

#define EQ(a, b)  ((a) == (b)).unwrap_public()
#define NEQ(a, b) ((a) != (b)).unwrap_public()

// Build a field element from a raw uint64 value via zero + v.
// After reduce() this equals v mod p.
static field_25519 fe(uint64_t v)
{
	return field_25519::zero() + v;
}

// Get a random nonzero uint64 from libsodium, clamped to 51 bits so it fits
// cleanly in a single limb without overflow surprises in unreduced form.
static uint64_t rnd_u64()
{
	uint64_t v = 0;
	randombytes_buf(&v, sizeof v);
	v &= (1ULL << 51) - 1;
	if (v == 0) v = 1;
	return v;
}

int main()
{
	if (sodium_init() < 0) return 1;

	std::println("=== field_25519 tests (libsodium randomness) ===\n");

	const auto zero = field_25519::zero();
	const auto one  = field_25519::one();
	const auto p    = field_25519::p();

	// -----------------------------------------------------------------------
	// wrap-around / reduction
	// -----------------------------------------------------------------------
	std::println("--- reduction ---");
	TEST("p == 0",       EQ(p.reduce(),              zero));
	TEST("p + 1 == 1",   EQ((p + 1u).reduce(),       one));
	TEST("p + 2 == 2",   EQ((p + 2u).reduce(),       fe(2)));
	TEST("p + 18 == 18", EQ((p + 18u).reduce(),      fe(18)));
	TEST("p + p == 0",   EQ((p + p).reduce(),         zero));
	TEST("2p + 1 == 1",  EQ((p + p + one).reduce(),  one));

	// values in [p, p+18] must each reduce to [0, 18]
	for (uint64_t i = 0; i <= 18; ++i)
		TEST(std::format("(p + {}) reduces to {}", i, i),
		     EQ((p + i).reduce(), fe(i)));

	// -----------------------------------------------------------------------
	// addition
	// -----------------------------------------------------------------------
	std::println("\n--- addition ---");
	TEST("0 + 0 == 0",     EQ(zero + zero,              zero));
	TEST("1 + 0 == 1",     EQ(one  + zero,              one));
	TEST("a + b == b + a", EQ(fe(4) + fe(9),            fe(9) + fe(4)));
	TEST("a - a == 0",     EQ((fe(6) - fe(6)).reduce(), zero));
	TEST("-a + a == 0",    EQ((-fe(3) + fe(3)).reduce(), zero));

	// -----------------------------------------------------------------------
	// multiplication
	// -----------------------------------------------------------------------
	std::println("\n--- multiplication ---");
	TEST("0 * a == 0",     EQ(zero   * fe(7),            zero));
	TEST("1 * a == a",     EQ(one    * fe(7),            fe(7)));
	TEST("2 * 3 == 6",     EQ(fe(2)  * fe(3),            fe(6)));
	TEST("a * b == b * a", EQ(fe(4)  * fe(11),           fe(11) * fe(4)));
	TEST("a^2 == a * a",   EQ(fe(5).square(),            fe(5) * fe(5)));
	TEST("(p-1)^2 == 1",   EQ(((p - one) * (p - one)).reduce(), one));

	// -----------------------------------------------------------------------
	// inversion
	// -----------------------------------------------------------------------
	std::println("\n--- inversion ---");
	TEST("0^-1 == 0",       EQ(zero.invert(),                    zero));
	TEST("1^-1 == 1",       EQ(one.invert(),                     one));
	TEST("2 * 2^-1 == 1",   EQ((fe(2) * fe(2).invert()).reduce(), one));
	TEST("7 * 7^-1 == 1",   EQ((fe(7) * fe(7).invert()).reduce(), one));
	TEST("(p-1)^-1 == p-1", EQ((p - one).invert().reduce(),      (p - one).reduce()));

	for (uint64_t v = 1; v <= 50; ++v)
		TEST(std::format("{} * {}^-1 == 1", v, v),
		     EQ((fe(v) * fe(v).invert()).reduce(), one));

	// -----------------------------------------------------------------------
	// distributivity / associativity
	// -----------------------------------------------------------------------
	std::println("\n--- distributivity / associativity ---");
	TEST("a*(b+c) == a*b+a*c",
	     EQ((fe(2) * (fe(3) + fe(4))).reduce(),
	        (fe(2) * fe(3) + fe(2) * fe(4)).reduce()));
	TEST("(a+b)+c == a+(b+c)",
	     EQ(((fe(2) + fe(3)) + fe(4)).reduce(),
	        (fe(2) + (fe(3) + fe(4))).reduce()));

	// -----------------------------------------------------------------------
	// ct_select
	// -----------------------------------------------------------------------
	std::println("\n--- ct_select ---");
	TEST("ct_select(a,b,true)==a",
	     EQ(ct_select(fe(3), fe(7), choice::true_choice()),  fe(3)));
	TEST("ct_select(a,b,false)==b",
	     EQ(ct_select(fe(3), fe(7), choice::false_choice()), fe(7)));

	// -----------------------------------------------------------------------
	// sqrt
	// -----------------------------------------------------------------------
	std::println("\n--- sqrt ---");
	TEST("sqrt(0) is some",  sqrt(zero).is_some_public());
	TEST("sqrt(0)^2 == 0",   EQ(sqrt(zero).value_or(one).square().reduce(), zero));
	TEST("sqrt(1) is some",  sqrt(one).is_some_public());
	TEST("sqrt(1)^2 == 1",   EQ(sqrt(one).value_or(zero).square().reduce(), one));

	{
		auto s = sqrt(fe(4));
		TEST("sqrt(4) is some", s.is_some_public());
		TEST("sqrt(4)^2 == 4",  EQ(s.value_or(zero).square().reduce(), fe(4)));
	}
	{
		auto s = sqrt(fe(9));
		TEST("sqrt(9) is some", s.is_some_public());
		TEST("sqrt(9)^2 == 9",  EQ(s.value_or(zero).square().reduce(), fe(9)));
	}

	// 2 is not a QR mod p
	TEST("sqrt(2) is none", !sqrt(fe(2)).is_some_public());

	// any x^2 must have a sqrt
	for (uint64_t v : {3ull, 5ull, 7ull, 13ull, 100ull, (1ull << 16)}) {
		auto x  = fe(v);
		auto x2 = x.square();
		auto s  = sqrt(x2);
		TEST(std::format("sqrt({}^2) is some", v), s.is_some_public());
		TEST(std::format("sqrt({}^2)^2 == {}^2", v, v),
		     EQ(s.value_or(zero).square().reduce(), x2.reduce()));
	}

	// -----------------------------------------------------------------------
	// Random algebraic invariants — inputs drawn from libsodium's CSPRNG
	// -----------------------------------------------------------------------
	std::println("\n--- random invariants (libsodium CSPRNG) ---");

	constexpr int N = 100;

	{
		bool ok = true;
		for (int i = 0; i < N; ++i) {
			auto a = fe(rnd_u64()), b = fe(rnd_u64());
			ok &= EQ((a + b).reduce(), (b + a).reduce());
		}
		TEST("a + b == b + a (100x random)", ok);
	}
	{
		bool ok = true;
		for (int i = 0; i < N; ++i) {
			auto a = fe(rnd_u64()), b = fe(rnd_u64()), c = fe(rnd_u64());
			ok &= EQ(((a + b) + c).reduce(), (a + (b + c)).reduce());
		}
		TEST("(a+b)+c == a+(b+c) (100x random)", ok);
	}
	{
		bool ok = true;
		for (int i = 0; i < N; ++i) {
			auto a = fe(rnd_u64()), b = fe(rnd_u64());
			ok &= EQ((a * b).reduce(), (b * a).reduce());
		}
		TEST("a * b == b * a (100x random)", ok);
	}
	{
		bool ok = true;
		for (int i = 0; i < N; ++i) {
			auto a = fe(rnd_u64()), b = fe(rnd_u64()), c = fe(rnd_u64());
			ok &= EQ((a * (b + c)).reduce(), (a * b + a * c).reduce());
		}
		TEST("a*(b+c) == a*b+a*c (100x random)", ok);
	}
	{
		bool ok = true;
		for (int i = 0; i < N; ++i) {
			auto a = fe(rnd_u64());
			ok &= EQ((a - a).reduce(), zero);
		}
		TEST("a - a == 0 (100x random)", ok);
	}
	{
		bool ok = true;
		for (int i = 0; i < N; ++i) {
			auto a = fe(rnd_u64());
			ok &= EQ(a.square().reduce(), (a * a).reduce());
		}
		TEST("a.square() == a*a (100x random)", ok);
	}
	{
		bool ok = true;
		for (int i = 0; i < N; ++i) {
			auto a = fe(rnd_u64()); // nonzero by construction
			ok &= EQ((a * a.invert()).reduce(), one);
		}
		TEST("a * a^-1 == 1 (100x random)", ok);
	}
	{
		bool ok = true;
		for (int i = 0; i < N; ++i) {
			auto x  = fe(rnd_u64());
			auto x2 = x.square();
			auto s  = sqrt(x2);
			ok &= s.is_some_public() &&
			      EQ(s.value_or(zero).square().reduce(), x2.reduce());
		}
		TEST("sqrt(rand^2)^2 == rand^2 (100x random)", ok);
	}
	{
		// reduce is idempotent after arbitrary mixed arithmetic
		bool ok = true;
		for (int i = 0; i < N; ++i) {
			auto a = fe(rnd_u64()), b = fe(rnd_u64());
			auto r = (a * b + a - b).reduce();
			ok &= EQ(r, r.reduce());
		}
		TEST("reduce idempotent after mixed arithmetic (100x random)", ok);
	}

	std::println("\n{} passed, {} failed", passed, failed);
	return failed == 0 ? 0 : 1;
}
