//go:build linux && cgo

#ifndef TW_BRIDGE_H
#define TW_BRIDGE_H
#include <stdint.h>
#include <stddef.h>
typedef struct twgpu twgpu;
typedef struct twgpu_info {
 int index;
 uint64_t global_mem;
 uint64_t free_mem;
 uint64_t max_alloc;
 uint32_t compute_units;
 char name[256];
} twgpu_info;
// enumerate opencl gpus in stable order
int twgpu_list(twgpu_info *infos, int max_devices, char *error, size_t errorlen);
twgpu *twgpu_open(const char *source, int device_index, int max_lanes, int N, char *error, size_t errorlen);
int twgpu_romix(twgpu *gpu, unsigned char *data, int lanes, int steps, char *error, size_t errorlen);
void twgpu_close(twgpu *gpu);
const char *twgpu_name(twgpu *gpu);
#endif
