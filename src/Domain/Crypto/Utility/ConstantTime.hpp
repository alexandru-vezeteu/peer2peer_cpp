#pragma once

#include "CtComparable.hpp"
#include "CtSelectable.hpp"


template<typename T>
concept ConstantTime = CtComparable<T> && CtSelectable<T>;