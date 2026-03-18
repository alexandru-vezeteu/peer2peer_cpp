#include <print>
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
	std::println("=== field_25519 tests ===\n");

	auto zero = field_25519::zero();
	auto one  = field_25519::one();
	auto p    = field_25519::p();

	// --- wrap-around / reduction ---
	TEST("p == 0",              EQ(p.reduce(),             zero));
	TEST("p + 1 == 1",          EQ((p + 1u).reduce(),      one));
	TEST("p + 2 == 2",          EQ((p + 2u).reduce(),      one + 1u));
	TEST("p + 18 == 18",        EQ((p + 18u).reduce(),     one + 17u));
	TEST("p + p == 0",          EQ((p + p).reduce(),       zero));
	TEST("2*p + 1 == 1",        EQ((p + p + one).reduce(), one));

	// --- addition ---
	TEST("0 + 0 == 0",          EQ(zero + zero,            zero));
	TEST("1 + 0 == 1",          EQ(one + zero,             one));
	TEST("a + b == b + a",      EQ((one + 6u) + (one + 2u), (one + 2u) + (one + 6u)));
	TEST("a - a == 0",          EQ((one + 5u - (one + 5u)).reduce(), zero));
	TEST("-a + a == 0",         EQ((-(one + 3u) + (one + 3u)).reduce(), zero));

	// --- multiplication ---
	TEST("0 * a == 0",          EQ(zero * (one + 7u),      zero));
	TEST("1 * a == a",          EQ(one  * (one + 7u),      one + 7u));
	TEST("2 * 3 == 6",          EQ((one + 1u) * (one + 2u), one + 5u));
	TEST("a * b == b * a",      EQ((one + 3u) * (one + 9u), (one + 9u) * (one + 3u)));
	TEST("a^2 == a * a",        EQ((one + 4u).square(), (one + 4u) * (one + 4u)));
	TEST("(p-1)^2 == 1",        EQ(((p - one) * (p - one)).reduce(), one));

	// --- inversion ---
	TEST("0^-1 == 0",           EQ(zero.invert(),          zero));
	TEST("1^-1 == 1",           EQ(one.invert(),           one));
	TEST("2 * 2^-1 == 1",       EQ(((one + 1u) * (one + 1u).invert()).reduce(), one));
	TEST("7 * 7^-1 == 1",       EQ(((one + 6u) * (one + 6u).invert()).reduce(), one));
	TEST("(p-1)^-1 == p-1",     EQ(((p - one).invert()).reduce(), (p - one).reduce()));

	// --- distributivity / associativity ---
	TEST("a*(b+c) == a*b+a*c",  EQ(((one+1u)*((one+2u)+(one+3u))).reduce(),
	                               ((one+1u)*(one+2u) + (one+1u)*(one+3u)).reduce()));
	TEST("(a+b)+c == a+(b+c)",  EQ(((one+1u)+(one+2u))+(one+3u),
	                               (one+1u)+((one+2u)+(one+3u))));

	// --- ct_select ---
	TEST("ct_select(a,b,true)==a",  EQ(ct_select(one+3u, one+7u, choice::true_choice()),  one+3u));
	TEST("ct_select(a,b,false)==b", EQ(ct_select(one+3u, one+7u, choice::false_choice()), one+7u));

	// --- to_bytes: known byte patterns ---
	// 0 → all zero bytes
	{
		auto b = zero.to_bytes();
		bool all_zero = true;
		for (auto byte : b) all_zero &= (byte == 0);
		TEST("to_bytes(0) == all zeros", all_zero);
	}
	// 1 → byte[0] == 1, rest zero
	{
		auto b = one.to_bytes();
		bool ok = (b[0] == 1);
		for (size_t i = 1; i < 32; ++i) ok &= (b[i] == 0);
		TEST("to_bytes(1) == {1, 0, 0, ...}", ok);
	}
	// top bit of byte 31 is always 0 (value < 2^255)
	{
		bool ok = true;
		for (uint64_t v : {0ull, 1ull, 18ull, (1ull << 40)}) {
			ok &= ((zero + v).to_bytes()[31] & 0x80) == 0;
		}
		ok &= (p.to_bytes()[31] & 0x80) == 0;
		TEST("top bit of byte 31 always 0", ok);
	}
	// RFC 7748 §6.1 known vector: base point u=9
	// to_bytes(9) == {9, 0, 0, ..., 0}
	{
		auto b = (zero + 9ull).to_bytes();
		bool ok = (b[0] == 9);
		for (size_t i = 1; i < 32; ++i) ok &= (b[i] == 0);
		TEST("to_bytes(9) == {9, 0, ...}", ok);
	}

	// --- from_bytes: known byte patterns ---
	// {0, 0, ..., 0} → 0
	{
		std::array<uint8_t, 32> b{};
		TEST("from_bytes({0...}) == 0", EQ(field_25519::from_bytes(b).value_or(one), zero));
	}
	// {1, 0, ..., 0} → 1
	{
		std::array<uint8_t, 32> b{};
		b[0] = 1;
		TEST("from_bytes({1,0...}) == 1", EQ(field_25519::from_bytes(b).value_or(zero), one));
	}
	// {9, 0, ..., 0} → 9
	{
		std::array<uint8_t, 32> b{};
		b[0] = 9;
		TEST("from_bytes({9,0...}) == 9", EQ(field_25519::from_bytes(b).value_or(zero), zero + 9ull));
	}
	// top bit of byte 31 is masked (ignored)
	{
		std::array<uint8_t, 32> b{};
		b[0] = 5;
		b[31] = 0x80;  // set reserved top bit
		TEST("from_bytes masks top bit of byte 31", EQ(field_25519::from_bytes(b).value_or(zero), zero + 5ull));
	}
	// non-canonical: bytes encoding p → reduces to 0
	{
		// p = 2^255 - 19: byte[0] = 0xED, byte[1..30] = 0xFF, byte[31] = 0x7F
		std::array<uint8_t, 32> b;
		b.fill(0xFF);
		b[0]  = 0xED;
		b[31] = 0x7F;
		TEST("from_bytes(p) == 0 (non-canonical)", EQ(field_25519::from_bytes(b).value_or(one), zero));
	}
	// non-canonical: p+1 → reduces to 1
	{
		std::array<uint8_t, 32> b;
		b.fill(0xFF);
		b[0]  = 0xEE;
		b[31] = 0x7F;
		TEST("from_bytes(p+1) == 1 (non-canonical)", EQ(field_25519::from_bytes(b).value_or(zero), one));
	}

	// --- round-trip: to_bytes(from_bytes(to_bytes(x))) == to_bytes(x) ---
	for (uint64_t v : {0ull, 1ull, 2ull, 18ull, 255ull, (1ull << 20), (1ull << 40)}) {
		auto x     = zero + v;
		auto bytes = x.to_bytes();
		auto x2    = field_25519::from_bytes(bytes).value_or(zero);
		auto label = std::format("round-trip {}", v);
		TEST(label, EQ(x2, x));
	}
	// non-canonical round-trips
	TEST("to_bytes(p) → from_bytes → 0",   EQ(field_25519::from_bytes(p.to_bytes()).value_or(one), zero));
	TEST("to_bytes(p+1) → from_bytes → 1", EQ(field_25519::from_bytes((p + 1u).to_bytes()).value_or(zero), one));

	// --- sqrt ---
	// 0 has a sqrt (itself)
	TEST("sqrt(0) is some",    sqrt(zero).is_some_public());
	TEST("sqrt(0)^2 == 0",     EQ(sqrt(zero).value_or(one).square().reduce(), zero));

	// 1 has a sqrt (itself)
	TEST("sqrt(1) is some",    sqrt(one).is_some_public());
	TEST("sqrt(1)^2 == 1",     EQ(sqrt(one).value_or(zero).square().reduce(), one));

	// 4 = 2^2, sqrt should be 2
	{
		auto two  = one + 1u;
		auto four = two * two;
		auto s    = sqrt(four);
		TEST("sqrt(4) is some",  s.is_some_public());
		TEST("sqrt(4)^2 == 4",   EQ(s.value_or(zero).square().reduce(), four.reduce()));
	}

	// 9 = 3^2
	{
		auto three = one + 2u;
		auto nine  = three * three;
		auto s     = sqrt(nine);
		TEST("sqrt(9) is some",  s.is_some_public());
		TEST("sqrt(9)^2 == 9",   EQ(s.value_or(zero).square().reduce(), nine.reduce()));
	}

	// 2 is not a QR mod p (Euler: 2^((p-1)/2) = -1 mod p)
	TEST("sqrt(2) is none", !sqrt(one + 1u).is_some_public());

	// generic QR: any x^2 must have a sqrt
	for (uint64_t v : {3ull, 5ull, 7ull, 13ull, 100ull, (1ull << 16)}) {
		auto x   = one + v;
		auto x2  = x.square();
		auto s   = sqrt(x2);
		auto lbl = std::format("sqrt({}^2) is some", v+1);
		TEST(lbl, s.is_some_public());
		auto lbl2 = std::format("sqrt({}^2)^2 == {}^2", v+1, v+1);
		TEST(lbl2, EQ(s.value_or(zero).square().reduce(), x2.reduce()));
	}

	std::println("\n{} passed, {} failed", passed, failed);
	return failed == 0 ? 0 : 1;
}
