#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "domain/crypto/condition.hpp"

using std::span;
using std::convertible_to;
using std::array;
using std::same_as;

template <typename T>
concept mac = requires(
	span<const uint8_t> key,
	span<const uint8_t> msg,
	span<const uint8_t> tag
) 
{
	{ T::key_size } -> convertible_to<size_t>;
	{ T::tag_size } -> convertible_to<size_t>;

	{ T::generate(key, msg) } 		-> same_as<array<uint8_t, T::tag_size>>;
	{ T::verify(key, msg, tag) } 	-> condition;
};
