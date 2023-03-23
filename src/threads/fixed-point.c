#include "threads/fixed-point.h"

/** Convert integer to fp. */
fp32_t itofp(int n) { return n * FP32_W; }

/** Convert fp to integer, round to 0. */
int fptoi_z(fp32_t x) { return x / FP32_W; }

/** Convert fp to integer, round to nearest. */
int 
fptoi_n(fp32_t x)
{
    if (x >= 0) return (x + FP32_W / 2) / FP32_W;
    return (x - FP32_W / 2) / FP32_W;
}

/** Add an integer to a fp. */
fp32_t fpaddi(fp32_t x, int n) { return x + n * FP32_W; }

/** Multiply 2 fps. */
fp32_t fpmulfp(fp32_t x, fp32_t y) { return (((int64_t)x) * y) / FP32_W; }

/**Divide a fp by a fp. */
fp32_t fpdivfp(fp32_t x, fp32_t y) { return (((int64_t)x) * FP32_W) / y; }