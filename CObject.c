#include "CObject.h"
#include "CDebugging.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <sodium.h>
#include <sodium/crypto_shorthash.h>
#include <sodium/crypto_shorthash_siphash24.h>

#if defined(_WIN32) || defined(_WIN64)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#elif defined(__linux__)

#endif

void
CObjectWorldAllocator_New(
  CObjectWorldAllocator *a_Allocator,
  CObjectWorldAllocatorKind a_Kind,
  ...
);

void
CObjectWorldAllocator_Allocate(
  CObjectWorldAllocator *a_Allocator,
  uint64_t a_Size,
  uint64_t a_Count,
  void **a_AddressOut
);

void
CObjectWorldAllocator_Reallocate(
  CObjectWorldAllocator *a_Allocator,
  void *a_Address,
  uint64_t a_Size,
  uint64_t a_Count,
  void **a_AddressOut
);

void
CObjectWorldAllocator_Deallocate(
  CObjectWorldAllocator *a_Allocator,
  void *a_Address
);

void
CObjectWorldAllocator_SystemReserve(
  CObjectWorldAllocator *a_Allocator,
  uint64_t a_Size,
  void **a_AddressOut
);

void
CObjectWorldAllocator_SystemCommit(
  CObjectWorldAllocator *a_Allocator,
  void *a_Address,
  uint64_t a_Size
);

void
CObjectWorldAllocator_Free(CObjectWorldAllocator *a_Allocator);

void
CObjectWorld_New(
  CObjectWorld *a_World,
  CObjectWorldAllocatorKind a_Kind,
  ...
)
{
  assert(a_World != NULL, "World is null");
  va_list l_Args;
  va_start(l_Args, a_Kind);
  CObjectWorldAllocator_New(&a_World->m_Allocator, a_Kind, va_arg(l_Args, uint64_t));
  va_end(l_Args);
  crypto_shorthash_keygen(a_World->m_Secret);
}

void
CObjectWorld_Free(
  CObjectWorld *a_World
)
{
  assert(a_World != NULL)
}

static arena
newarena(
  ptrdiff_t cap
)
{
  arena a = {0};
  cap += -cap & (ARENA_PAGESIZE - 1);
  a.begin = a.commit = a.end = os_reserve(cap);
  if(a.begin) { a.end += cap; }
  return a;
}

static void *
alloc(
  arena *a,
  ptrdiff_t size,
  ptrdiff_t align,
  ptrdiff_t count
)
{
  ptrdiff_t padding = -(size_t)a->begin & (align - 1);
  ptrdiff_t committed = a->commit - a->begin;
  if(count > (committed - padding) / size)
  {
    ptrdiff_t reserved = a->end - a->begin;
    if(count > (reserved - padding) / size) { return 0; }

    ptrdiff_t needed = size * count + padding - committed;
    needed += -needed & (ARENA_PAGESIZE - 1);
    if(!os_commit(a->commit, needed)) { return 0; }
    a->commit += needed;
  }

  void *ptr = a->begin + padding;
  a->begin += padding + size * count;
  return memset(ptr, 0, size * count);
}

// Test

static ptrdiff_t
test(
  arena *a,
  unsigned long long rng
)
{
  ptrdiff_t total = 0;
  void *save = a->begin;
  for(;;)
  {
    rng = rng * 0x3243f6a8885a308d + 1;
    ptrdiff_t size = 1 + ((rng >> 50) & ((1 << 10) - 1));
    ptrdiff_t count = 1 + ((rng >> 40) & ((1 << 10) - 1));
    ptrdiff_t align = 1 << ((rng >> 30) & ((1 << 2) - 1));
    if(!alloc(a, size, align, count)) { break; }
    total += size * count;
  }
  a->begin = save;
  return total;   // dprintf LINE,"%f\n",total/1024./1024.
}

static void
run(
  arena a
)
{
  for(int i = 0; i < 8; i++) { test(&a, i + 1); }
}

#ifdef _WIN32
// $ cc -g3 -nostartfiles -o arena.exe arena.c
// $ cl /Z7 arena.c /link /subsystem:console kernel32.lib libvcruntime.lib
#  define W32(r) __declspec(dllimport) r __stdcall
W32(void) ExitProcess(int);
W32(void *) VirtualAlloc(void *, ptrdiff_t, int, int);

#  define MEM_COMMIT 0x1000
#  define MEM_RESERVE 0x2000
#  define PAGE_NOACCESS 0x0001
#  define PAGE_READWRITE 0x0004

static void *
os_reserve(
  ptrdiff_t cap
)
{
  return VirtualAlloc(0, cap, MEM_RESERVE, PAGE_NOACCESS);
}

static _Bool
os_commit(
  void *ptr,
  ptrdiff_t len
)
{
  return VirtualAlloc(ptr, len, MEM_COMMIT, PAGE_READWRITE);
}

void
mainCRTStartup(
  void
)
{
  arena a = newarena((ptrdiff_t)1 << 33);
  run(a);
  ExitProcess(0);
}

#else   // POSIX
// $ cc -g3 -o arena arena.c
#  include <sys/mman.h>

static void *
os_reserve(
  ptrdiff_t cap
)
{
  void *r = mmap(0, cap, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
  return r == MAP_FAILED ? 0 : r;
}

static _Bool
os_commit(
  void *ptr,
  ptrdiff_t len
)
{
  return !mprotect(ptr, len, PROT_READ | PROT_WRITE);
}

int
main(
  void
)
{
  arena a = newarena((ptrdiff_t)1 << 33);
  run(a);
}
#endif
