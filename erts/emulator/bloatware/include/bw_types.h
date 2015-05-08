#pragma once

#include <stdint.h>
#include <memory>

typedef size_t Eterm;

#define SWORD_CONSTANT(Const) Const##L
#define UWORD_CONSTANT(Const) Const##UL
#define ERTS_UWORD_MAX ULONG_MAX
#define ERTS_SWORD_MAX LONG_MAX
#define ERTS_SIZEOF_ETERM SIZEOF_LONG
#define ErtsStrToSint strtol
