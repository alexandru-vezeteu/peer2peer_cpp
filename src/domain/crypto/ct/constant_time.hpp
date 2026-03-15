#pragma once

#include "ct_comparable.hpp"
#include "ct_selectable.hpp"

template<typename T, typename C>
concept constant_time = ct_comparable<T> && ct_selectable<T, C>;
