#pragma once

#define PTR_ADD(PTR, OFFSET) (void*)((uint8_t*)(PTR) + (size_t)(OFFSET))
#define PTR_SUB(PTR, OFFSET) (void*)((uint8_t*)(PTR) - (size_t)(OFFSET))
#define PTR_DIFF(PTR1, PTR2) (ptrdiff_t)((uint8_t*)(PTR1) - (uint8_t*)(PTR2))