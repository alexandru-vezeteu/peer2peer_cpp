#pragma once
#include <cstdint>
#include "domain/crypto/ct/condition.hpp"
// inspo: https://doc.dalek.rs/subtle/
struct choice
{
	[[nodiscard]] constexpr bool unwrap_public() const noexcept { return val != 0; }

	constexpr choice operator! ()         const noexcept { return choice(uint8_t(val ^ 0xFF));  }
	constexpr choice operator&&(choice o) const noexcept { return choice(uint8_t(val & o.val)); }
	constexpr choice operator||(choice o) const noexcept { return choice(uint8_t(val | o.val)); }

	constexpr uint64_t mask()
	{
		return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(val)));
	}

	//val == 0 => true dar  fac la fel de multe operatii indiferent de biti
	explicit constexpr choice(uint64_t diff) noexcept
	{
		//daca diff == 0 => is_non_zero da 0
		//daca diff !=0 => 0-diff<0 => ultimul bit de semn e setat
		// trn diff| .. pt ca -0 is a thing..
		uint64_t is_non_zero = (diff | (0ULL - diff)) >> 63;
    	val = static_cast<uint8_t>(0ULL - (is_non_zero ^ 1)) & 0xFF;
	}

	static constexpr choice from_equal(uint64_t a, uint64_t b)
	{
		return choice{a-b};
	}

	static constexpr choice true_choice()  noexcept { return choice{ uint8_t(0xFF) }; }
    static constexpr choice false_choice() noexcept { return choice{ uint8_t(0x00) }; }
	
	static constexpr choice from_zero(uint64_t value) noexcept
	{
		return choice{ value };
	}

    static constexpr choice from_nonzero(uint64_t value) noexcept
    {
        return !choice{ value };
    }

private:
	explicit constexpr choice(uint8_t raw) noexcept : val(raw) {}
	uint8_t val;
};
template<> inline constexpr bool is_condition_type<choice> = true;
