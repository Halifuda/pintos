#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <debug.h>
#include <list.h>
#include <stdint.h>

#define FP32_P 14
#define FP32_W (1 << FP32_P)

typedef int fp32_t;

fp32_t itofp(int);
int fptoi_z(fp32_t);
int fptoi_n(fp32_t);

fp32_t fpaddi(fp32_t, int);
fp32_t fpmulfp(fp32_t, fp32_t);
fp32_t fpdivfp(fp32_t, fp32_t);

#endif