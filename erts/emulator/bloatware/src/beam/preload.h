#pragma once

typedef struct preload {
    const char *name;	/* Name of module */
    uint32_t size;	/* Size of code */
    uint8_t* code;	/* Code pointer */
} Preload;

extern Preload pre_loaded[];
