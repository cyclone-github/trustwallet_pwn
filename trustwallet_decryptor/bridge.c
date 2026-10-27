//go:build linux && cgo

#include "bridge.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// opencl 1.2 api by khronos; manually declared without development headers
// requires the system opencl icd loader
typedef void *cl_platform_id;
typedef void *cl_device_id;
typedef void *cl_context;
typedef void *cl_command_queue;
typedef void *cl_mem;
typedef void *cl_program;
typedef void *cl_kernel;
typedef int32_t cl_int;
typedef uint32_t cl_uint;
typedef uint64_t cl_ulong;
typedef cl_ulong cl_device_type;
typedef cl_ulong cl_mem_flags;
typedef uint32_t cl_bool;
typedef intptr_t cl_context_properties;
typedef intptr_t cl_queue_properties;
typedef uint32_t cl_device_info;
#define CL_SUCCESS 0
#define CL_TRUE 1
#define CL_DEVICE_TYPE_GPU ((cl_device_type)4)
#define CL_DEVICE_NAME 0x102B
#define CL_DEVICE_GLOBAL_MEM_SIZE 0x101F
#define CL_MEM_READ_WRITE (1UL << 0)
#define CL_PROGRAM_BUILD_LOG 0x1183
extern cl_int clGetPlatformIDs(cl_uint, cl_platform_id *, cl_uint *);
extern cl_int clGetDeviceIDs(cl_platform_id, cl_device_type, cl_uint, cl_device_id *, cl_uint *);
extern cl_int clGetDeviceInfo(cl_device_id, cl_device_info, size_t, void *, size_t *);
extern cl_context clCreateContext(const cl_context_properties *, cl_uint, const cl_device_id *, void*, void *, cl_int *);
extern cl_command_queue clCreateCommandQueue(cl_context, cl_device_id, cl_ulong, cl_int *);
extern cl_program clCreateProgramWithSource(cl_context, cl_uint, const char **, const size_t *, cl_int *);
extern cl_int clBuildProgram(cl_program, cl_uint, const cl_device_id *, const char *, void *, void *);
extern cl_int clGetProgramBuildInfo(cl_program, cl_device_id, cl_uint, size_t, void *, size_t *);
extern cl_kernel clCreateKernel(cl_program, const char *, cl_int *);
extern cl_mem clCreateBuffer(cl_context, cl_mem_flags, size_t, void *, cl_int *);
extern cl_int clSetKernelArg(cl_kernel, cl_uint, size_t, const void *);
extern cl_int clEnqueueWriteBuffer(cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void *, cl_uint, const void *, void *);
extern cl_int clEnqueueReadBuffer(cl_command_queue, cl_mem, cl_bool, size_t, size_t, void *, cl_uint, const void *, void *);
extern cl_int clEnqueueNDRangeKernel(cl_command_queue, cl_kernel, cl_uint, const size_t *, const size_t *, const size_t *, cl_uint, const void *, void *);
extern cl_int clFinish(cl_command_queue);
extern cl_int clReleaseMemObject(cl_mem);
extern cl_int clReleaseKernel(cl_kernel);
extern cl_int clReleaseProgram(cl_program);
extern cl_int clReleaseCommandQueue(cl_command_queue);
extern cl_int clReleaseContext(cl_context);

#define TW_MAX_GPU 64
#define TW_SCRATCH_SEGMENTS 8
#define TW_MIB (1024ULL*1024ULL)
#define CL_DEVICE_MAX_MEM_ALLOC_SIZE 0x1010
#define CL_DEVICE_MAX_COMPUTE_UNITS 0x1002
// nvidia 0x4000 identifies compute capability not free memory
// amd free memory returns values in kib
#define CL_DEVICE_EXTENSIONS 0x1030
#define CL_DEVICE_GLOBAL_FREE_MEMORY_AMD 0x4039

struct twgpu {
 cl_context ctx;
 cl_device_id device;
 cl_command_queue queue;
 cl_program program;
 cl_kernel fill, mix;
 cl_mem state, scratch[TW_SCRATCH_SEGMENTS];
 int max_lanes, N, segments, lanes_per_buffer;
 char name[256];
};
static void fail(char *s,size_t n,const char *where,cl_int rc) {
 if(s && n) snprintf(s,n,"%s: OpenCL error %d",where,(int)rc);
}
void twgpu_close(twgpu *g) {
 if(!g)return;
 for(int i=0;i<TW_SCRATCH_SEGMENTS;i++)if(g->scratch[i])clReleaseMemObject(g->scratch[i]);
 if(g->state)clReleaseMemObject(g->state);
 if(g->fill)clReleaseKernel(g->fill);
 if(g->mix)clReleaseKernel(g->mix);
 if(g->program)clReleaseProgram(g->program);
 if(g->queue)clReleaseCommandQueue(g->queue);
 if(g->ctx)clReleaseContext(g->ctx);
 free(g);
}
const char *twgpu_name(twgpu *g){return g?g->name:"";}
static int enumerate_gpu_ids(cl_device_id *out,int cap,char *err,size_t errlen){
 cl_uint count=0;
 cl_int rc=clGetPlatformIDs(0,NULL,&count);
 if(rc!=CL_SUCCESS||!count){if(err&&errlen)snprintf(err,errlen,"no OpenCL platform (clGetPlatformIDs=%d)",rc);return -1;}
 cl_platform_id *platforms=calloc(count,sizeof(*platforms));
 if(!platforms){if(err&&errlen)snprintf(err,errlen,"out of memory");return -1;}
 rc=clGetPlatformIDs(count,platforms,NULL);
 if(rc!=CL_SUCCESS){free(platforms);fail(err,errlen,"enumerate platforms",rc);return -1;}
 int total=0;
 for(cl_uint i=0;i<count;i++){
  cl_uint devices=0;
  rc=clGetDeviceIDs(platforms[i],CL_DEVICE_TYPE_GPU,0,NULL,&devices);
  if(rc!=CL_SUCCESS||devices==0)continue;
  if(devices>(cl_uint)(cap-total)){if(err&&errlen)snprintf(err,errlen,"too many OpenCL GPUs (limit %d)",cap);free(platforms);return -1;}
  rc=clGetDeviceIDs(platforms[i],CL_DEVICE_TYPE_GPU,devices,out+total,NULL);
  if(rc!=CL_SUCCESS){free(platforms);fail(err,errlen,"enumerate GPU devices",rc);return -1;}
  total+=(int)devices;
 }
 free(platforms);
 if(!total&&err&&errlen)snprintf(err,errlen,"no OpenCL GPU devices found");
 return total;
}
int twgpu_list(twgpu_info *infos,int max_devices,char *err,size_t errlen){
 if(!infos||max_devices<1||max_devices>TW_MAX_GPU)return -1;
 cl_device_id devices[TW_MAX_GPU];
 int count=enumerate_gpu_ids(devices,TW_MAX_GPU,err,errlen);
 if(count<0)return -1;
 if(count>max_devices){if(err&&errlen)snprintf(err,errlen,"too many GPUs for output array");return -1;}
 for(int i=0;i<count;i++){
  memset(&infos[i],0,sizeof(infos[i]));
  infos[i].index=i;
  clGetDeviceInfo(devices[i],CL_DEVICE_NAME,sizeof(infos[i].name),infos[i].name,NULL);
  infos[i].name[sizeof(infos[i].name)-1]=0;
  cl_ulong total=0, maxalloc=0;
  cl_uint units=0, free_kib[2]={0,0};
  clGetDeviceInfo(devices[i],CL_DEVICE_GLOBAL_MEM_SIZE,sizeof(total),&total,NULL);
  clGetDeviceInfo(devices[i],CL_DEVICE_MAX_MEM_ALLOC_SIZE,sizeof(maxalloc),&maxalloc,NULL);
  clGetDeviceInfo(devices[i],CL_DEVICE_MAX_COMPUTE_UNITS,sizeof(units),&units,NULL);
  infos[i].global_mem=(uint64_t)total;
  infos[i].max_alloc=(uint64_t)maxalloc;
  infos[i].compute_units=units;
  // no portable free gpu memory query
  size_t ext_size=0;
  if(clGetDeviceInfo(devices[i],CL_DEVICE_EXTENSIONS,0,NULL,&ext_size)==CL_SUCCESS && ext_size>0 && ext_size<65536){
    char *ext=calloc(ext_size+1,1);
    if(ext){
      if(clGetDeviceInfo(devices[i],CL_DEVICE_EXTENSIONS,ext_size,ext,NULL)==CL_SUCCESS && strstr(ext,"cl_amd_device_attribute_query")!=NULL){
        if(clGetDeviceInfo(devices[i],CL_DEVICE_GLOBAL_FREE_MEMORY_AMD,sizeof(free_kib),free_kib,NULL)==CL_SUCCESS && free_kib[0]>0)
          infos[i].free_mem=(uint64_t)free_kib[0]*1024ULL;
      }
      free(ext);
    }
  }
 }
 return count;
}
twgpu *twgpu_open(const char *source,int device_index,int max_lanes,int N,char *err,size_t errlen){
 if(max_lanes<1||N<2||(N&(N-1))){if(err&&errlen)snprintf(err,errlen,"invalid lanes or N");return NULL;}
 cl_device_id devices[TW_MAX_GPU];
 int count=enumerate_gpu_ids(devices,TW_MAX_GPU,err,errlen);
 if(count<0)return NULL;
 if(device_index<0||device_index>=count){if(err&&errlen)snprintf(err,errlen,"invalid GPU index %d",device_index);return NULL;}
 cl_device_id d=devices[device_index];
 cl_int rc;
 twgpu *g=calloc(1,sizeof(*g));
 if(!g){if(err&&errlen)snprintf(err,errlen,"out of memory");return NULL;}
 g->device=d;g->max_lanes=max_lanes;g->N=N;
 clGetDeviceInfo(d,CL_DEVICE_NAME,sizeof(g->name),g->name,NULL);
 g->name[sizeof(g->name)-1]=0;
 g->ctx=clCreateContext(NULL,1,&d,NULL,NULL,&rc);
 if(!g->ctx||rc!=CL_SUCCESS){fail(err,errlen,"clCreateContext",rc);goto error;}
 g->queue=clCreateCommandQueue(g->ctx,d,0,&rc);
 if(!g->queue||rc!=CL_SUCCESS){fail(err,errlen,"clCreateCommandQueue",rc);goto error;}
 size_t srclen=strlen(source);
 g->program=clCreateProgramWithSource(g->ctx,1,&source,&srclen,&rc);
 if(!g->program||rc!=CL_SUCCESS){fail(err,errlen,"clCreateProgramWithSource",rc);goto error;}
 rc=clBuildProgram(g->program,1,&d,"-cl-std=CL1.2",NULL,NULL);
 if(rc!=CL_SUCCESS){
  if(err&&errlen){
    size_t n=0;clGetProgramBuildInfo(g->program,d,CL_PROGRAM_BUILD_LOG,0,NULL,&n);
    char *log=malloc(n+1);
    if(log){clGetProgramBuildInfo(g->program,d,CL_PROGRAM_BUILD_LOG,n,log,NULL);log[n]=0;snprintf(err,errlen,"OpenCL build error %d: %s",(int)rc,log);free(log);}
    else fail(err,errlen,"clBuildProgram",rc);
  }
  goto error;
 }
 g->fill=clCreateKernel(g->program,"romix_fill",&rc);
 if(!g->fill||rc!=CL_SUCCESS){fail(err,errlen,"create fill kernel",rc);goto error;}
 g->mix=clCreateKernel(g->program,"romix_mix",&rc);
 if(!g->mix||rc!=CL_SUCCESS){fail(err,errlen,"create mix kernel",rc);goto error;}
 size_t lane_bytes=(size_t)N*1024;
 if(!lane_bytes||((size_t)max_lanes>SIZE_MAX/lane_bytes)){
  if(err&&errlen)snprintf(err,errlen,"size overflow");goto error;
 }
 size_t statebytes=(size_t)max_lanes*1024;
 cl_ulong maxalloc=0;
 clGetDeviceInfo(d,CL_DEVICE_MAX_MEM_ALLOC_SIZE,sizeof(maxalloc),&maxalloc,NULL);
 if(maxalloc==0)maxalloc=(cl_ulong)SIZE_MAX;
 // reserve driver allocation overhead
 size_t per_segment_limit=(size_t)(maxalloc - maxalloc/20);
 size_t lanes_per_segment=per_segment_limit/lane_bytes;
 if(lanes_per_segment<1){if(err&&errlen)snprintf(err,errlen,"N=%d requires %zu bytes per lane but device max allocation is %llu",N,lane_bytes,(unsigned long long)maxalloc);goto error;}
 if(lanes_per_segment>(size_t)max_lanes)lanes_per_segment=(size_t)max_lanes;
 g->lanes_per_buffer=(int)lanes_per_segment;
 g->segments=(max_lanes + g->lanes_per_buffer-1)/g->lanes_per_buffer;
 if(g->segments>TW_SCRATCH_SEGMENTS){if(err&&errlen)snprintf(err,errlen,"scratch requires %d buffers (limit %d)",g->segments,TW_SCRATCH_SEGMENTS);goto error;}
 g->state=clCreateBuffer(g->ctx,CL_MEM_READ_WRITE,statebytes,NULL,&rc);
 if(!g->state||rc!=CL_SUCCESS){fail(err,errlen,"create state buffer",rc);goto error;}
 for(int i=0;i<g->segments;i++){
  int lanes=max_lanes-i*g->lanes_per_buffer;
  if(lanes>g->lanes_per_buffer)lanes=g->lanes_per_buffer;
  size_t bytes=(size_t)lanes*lane_bytes;
  g->scratch[i]=clCreateBuffer(g->ctx,CL_MEM_READ_WRITE,bytes,NULL,&rc);
  if(!g->scratch[i]||rc!=CL_SUCCESS){
    if(err&&errlen)snprintf(err,errlen,"scratch allocation #%d of %d (%zu MiB): OpenCL error %d",i+1,g->segments,bytes/TW_MIB,(int)rc);
    goto error;
  }
 }
 return g;
error:twgpu_close(g);return NULL;
}
int twgpu_romix(twgpu *g,unsigned char *data,int lanes,int steps,char *err,size_t errlen){
 if(!g||!data||lanes<1||lanes>g->max_lanes||steps<1){if(err&&errlen)snprintf(err,errlen,"invalid ROMix argument");return -1;}
 cl_int rc=clEnqueueWriteBuffer(g->queue,g->state,CL_TRUE,0,(size_t)lanes*1024,data,0,NULL,NULL);
 if(rc!=CL_SUCCESS){fail(err,errlen,"write state buffer",rc);return -1;}
 const cl_uint N=(cl_uint)g->N;
 const cl_uint lpb=(cl_uint)g->lanes_per_buffer;
 const size_t global=(size_t)lanes;
 cl_kernel kernels[]={g->fill,g->mix};
 for(int phase=0;phase<2;phase++){
  cl_kernel k=kernels[phase];
  rc=clSetKernelArg(k,0,sizeof(g->state),&g->state);
  for(int s=0;s<TW_SCRATCH_SEGMENTS;s++){
    // unused arguments use the last populated buffer
    cl_mem obj=g->scratch[s<g->segments?s:g->segments-1];
    rc|=clSetKernelArg(k,s+1,sizeof(obj),&obj);
  }
  rc|=clSetKernelArg(k,9,sizeof(lpb),&lpb);
  rc|=clSetKernelArg(k,10,sizeof(N),&N);
  if(rc!=CL_SUCCESS){fail(err,errlen,"set ROMix kernel args",rc);return -1;}
  for(cl_uint offset=0;offset<N;){
    cl_uint count=(cl_uint)steps;
    if(count>N-offset)count=N-offset;
    rc=clSetKernelArg(k,11,sizeof(offset),&offset);
    rc|=clSetKernelArg(k,12,sizeof(count),&count);
    if(rc!=CL_SUCCESS){fail(err,errlen,"set kernel offset",rc);return -1;}
    rc=clEnqueueNDRangeKernel(g->queue,k,1,NULL,&global,NULL,0,NULL,NULL);
    if(rc!=CL_SUCCESS){fail(err,errlen,"enqueue ROMix",rc);return -1;}
    offset+=count;
  }
 }
 rc=clEnqueueReadBuffer(g->queue,g->state,CL_TRUE,0,(size_t)lanes*1024,data,0,NULL,NULL);
 if(rc!=CL_SUCCESS){fail(err,errlen,"read ROMix output",rc);return -1;}
 return 0;
}
