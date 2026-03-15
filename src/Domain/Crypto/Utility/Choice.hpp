#pragma once
#include <cstdint>

// inspo: https://doc.dalek.rs/subtle/
struct Choice
{
	
	[[nodiscard]] constexpr bool unwrap_public() const noexcept { return val != 0; }

	constexpr Choice operator! ()          const noexcept { return Choice(uint8_t(val ^ 0xFF));        }
	constexpr Choice operator&&(Choice o)  const noexcept { return Choice(uint8_t(val & o.val)); }
	constexpr Choice operator||(Choice o)  const noexcept { return Choice(uint8_t(val | o.val)); }

	explicit constexpr Choice(bool b) noexcept : val(b ? 0xFF : 0x00) {}  
	

private:   
	explicit constexpr Choice(uint8_t raw) noexcept : val(raw) {}
  	uint8_t val;
};