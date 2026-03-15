#pragma once


#include "../Utility/Choice.hpp"
#include "../Utility/CtOptional.hpp"
#include "Field.hpp"
#include "../Utility/ConstantTime.hpp"
#include "../Utility/CtSerializable.hpp"










template<typename T>
concept CryptoField = Field<T> && ConstantTime<T> && CtSerializable<T> && requires(T a)
{
	{ a.is_one() } -> std::same_as<Choice>;
	{ a.sqrt() } -> std::same_as<CtOptional<T>>;
};