// cyclone opencl romix kernel following scrypt rfc 7914 by colin percival
// opencl api by khronos; host pbkdf2 uses golang.org/x/crypto
#define R 8
#define WORDS (32*R)
inline uint rol32(uint a, uint n) { return (a << n) | (a >> (32-n)); }

inline void salsa208(__private uint *s) {
  uint x[16];
  for (int i=0;i<16;i++) x[i]=s[i];
  for (int i=0;i<8;i+=2) {
    x[ 4] ^= rol32(x[ 0]+x[12], 7);
    x[ 8] ^= rol32(x[ 4]+x[ 0], 9);
    x[12] ^= rol32(x[ 8]+x[ 4],13);
    x[ 0] ^= rol32(x[12]+x[ 8],18);
    x[ 9] ^= rol32(x[ 5]+x[ 1], 7);
    x[13] ^= rol32(x[ 9]+x[ 5], 9);
    x[ 1] ^= rol32(x[13]+x[ 9],13);
    x[ 5] ^= rol32(x[ 1]+x[13],18);
    x[14] ^= rol32(x[10]+x[ 6], 7);
    x[ 2] ^= rol32(x[14]+x[10], 9);
    x[ 6] ^= rol32(x[ 2]+x[14],13);
    x[10] ^= rol32(x[ 6]+x[ 2],18);
    x[ 3] ^= rol32(x[15]+x[11], 7);
    x[ 7] ^= rol32(x[ 3]+x[15], 9);
    x[11] ^= rol32(x[ 7]+x[ 3],13);
    x[15] ^= rol32(x[11]+x[ 7],18);

    x[ 1] ^= rol32(x[ 0]+x[ 3], 7);
    x[ 2] ^= rol32(x[ 1]+x[ 0], 9);
    x[ 3] ^= rol32(x[ 2]+x[ 1],13);
    x[ 0] ^= rol32(x[ 3]+x[ 2],18);
    x[ 6] ^= rol32(x[ 5]+x[ 4], 7);
    x[ 7] ^= rol32(x[ 6]+x[ 5], 9);
    x[ 4] ^= rol32(x[ 7]+x[ 6],13);
    x[ 5] ^= rol32(x[ 4]+x[ 7],18);
    x[11] ^= rol32(x[10]+x[ 9], 7);
    x[ 8] ^= rol32(x[11]+x[10], 9);
    x[ 9] ^= rol32(x[ 8]+x[11],13);
    x[10] ^= rol32(x[ 9]+x[ 8],18);
    x[12] ^= rol32(x[15]+x[14], 7);
    x[13] ^= rol32(x[12]+x[15], 9);
    x[14] ^= rol32(x[13]+x[12],13);
    x[15] ^= rol32(x[14]+x[13],18);
  }
  for (int i=0;i<16;i++) s[i]+=x[i];
}
// in-place blockmix reduces gpu private memory pressure
inline void blockmix(__private uint *x) {
  uint t[16];
  for (int k = 0; k < 16; k++) t[k] = x[(2*R-1)*16+k];
  for (int i = 0; i < 2*R; i++) {
    for (int k = 0; k < 16; k++) t[k] ^= x[i*16+k];
    salsa208(t);
    for (int k = 0; k < 16; k++) x[i*16+k] = t[k];
  }

  uint visited = 0;
  uint saved[16];
  for (int start = 0; start < 2*R; start++) {
    uint bit = (uint)1 << start;
    if (visited & bit) continue;
    for (int k = 0; k < 16; k++) saved[k] = x[start*16+k];
    int i = start;
    do {
      visited |= (uint)1 << i;
      int dest = (i & 1) ? R + (i >> 1) : (i >> 1);
      for (int k = 0; k < 16; k++) {
        uint tmp = x[dest*16+k];
        x[dest*16+k] = saved[k];
        saved[k] = tmp;
      }
      i = dest;
    } while (i != start);
  }
}
// bounded romix launch sizes avoid watchdog timeouts
// use multiple buffers to avoid single allocation limits
inline __global uint *romix_scratch(uint gid, uint lanes_per_buffer, uint N,
    __global uint *b0, __global uint *b1, __global uint *b2, __global uint *b3,
    __global uint *b4, __global uint *b5, __global uint *b6, __global uint *b7) {
  uint idx = gid / lanes_per_buffer;
  uint local_lane = gid - idx * lanes_per_buffer;
  __global uint *ptr = b0;
  switch (idx) {
    case 1: ptr = b1; break;
    case 2: ptr = b2; break;
    case 3: ptr = b3; break;
    case 4: ptr = b4; break;
    case 5: ptr = b5; break;
    case 6: ptr = b6; break;
    case 7: ptr = b7; break;
    default: break;
  }
  return ptr + ((ulong)local_lane * (ulong)N * (ulong)WORDS);
}

__kernel void romix_fill(__global uint *state, __global uint *scratch0, __global uint *scratch1,
    __global uint *scratch2, __global uint *scratch3,
    __global uint *scratch4, __global uint *scratch5,
    __global uint *scratch6, __global uint *scratch7,
    uint lanes_per_buffer, uint N, uint start, uint count) {
  uint gid=get_global_id(0);
  __global uint *sp=state+gid*WORDS;
  __global uint *vp=romix_scratch(gid,lanes_per_buffer,N,
      scratch0,scratch1,scratch2,scratch3,scratch4,scratch5,scratch6,scratch7);
  uint x[WORDS];
  for(int k=0;k<WORDS;k++) x[k]=sp[k];
  for(uint i=start;i<start+count;i++) {
    __global uint *v=vp+(ulong)i*WORDS;
    for(int k=0;k<WORDS;k++) v[k]=x[k];
    blockmix(x);
  }
  for(int k=0;k<WORDS;k++) sp[k]=x[k];
}
__kernel void romix_mix(__global uint *state, __global uint *scratch0, __global uint *scratch1,
    __global uint *scratch2, __global uint *scratch3,
    __global uint *scratch4, __global uint *scratch5,
    __global uint *scratch6, __global uint *scratch7,
    uint lanes_per_buffer, uint N, uint start, uint count) {
  uint gid=get_global_id(0);
  __global uint *sp=state+gid*WORDS;
  __global uint *vp=romix_scratch(gid,lanes_per_buffer,N,
      scratch0,scratch1,scratch2,scratch3,scratch4,scratch5,scratch6,scratch7);
  uint x[WORDS];
  for(int k=0;k<WORDS;k++) x[k]=sp[k];
  for(uint i=start;i<start+count;i++) {
    uint j=x[(2*R-1)*16] & (N-1);
    __global uint *v=vp+((ulong)j*WORDS);
    for(int k=0;k<WORDS;k++) x[k]^=v[k];
    blockmix(x);
  }
  for(int k=0;k<WORDS;k++) sp[k]=x[k];
}
