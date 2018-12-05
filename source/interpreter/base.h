#pragma once


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef double f64_t;
typedef float f32_t;


#define m_panic_header() printf("Internal error at [%s:%d]: ", __FILE__, __LINE__)
#define m_panic_error(fmt, ...) { m_panic_header(); printf(fmt, __VA_ARGS__); putchar('\n'); abort(); }
#define m_panic_assert(cond, fmt, ...) if (!(cond)) m_panic_error(fmt, __VA_ARGS__)