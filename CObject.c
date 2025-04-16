#include "CObject.h"
#include "CDebugging.h"

#include <stdalign.h>
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
#  include <sys/mman.h>
#endif

void
CObjectWorldAllocator_New(
  CObjectWorldAllocator *a_Allocator,
  CObjectWorldAllocatorKind a_Kind,
  ...
)
{
  assert(a_Allocator != NULL);
  memset(a_Allocator, 0, sizeof(CObjectWorldAllocator));
  a_Allocator->m_Kind = a_Kind;
  if(a_Kind == k_AllocatorKind_Arena)
  {
    va_list l_Args;
    va_start(l_Args, a_Kind);
    uint64_t l_Capacity = va_arg(l_Args, uint64_t);
    l_Capacity += -l_Capacity & (c_CObjectWorldAllocator_PageSize - 1);
    a_Allocator->m_Arena =
#if defined(_WIN32) || defined(_WIN64)
      VirtualAlloc(0, l_Capacity, MEM_RESERVE, PAGE_NOACCESS)
#elif defined(__linux__)
      mmap(0, cap, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0)
#endif
      ;
    assert(
      a_Allocator->m_Arena != NULL, L"Could not reserve %llu bytes of memory.", l_Capacity
    );
    a_Allocator->m_ArenaCommit = a_Allocator->m_Arena;
    a_Allocator->m_ArenaEnd = a_Allocator->m_Arena + l_Capacity;
    a_Allocator->m_ArenaSize = 0;
    a_Allocator->m_ArenaCapacity = l_Capacity;
  }
}

void
CObjectWorldAllocator_Allocate(
  CObjectWorldAllocator *a_Allocator,
  uint64_t a_Alignment,
  uint64_t a_Size,
  uint64_t a_Count,
  void **a_AddressOut
)
{
  assert(a_Allocator != NULL);
  assert(
    a_Size > 0,
    L"`a_Size` cannot be 0. Perhaps, you've meant to use "
    L"`CObjectWorldAllocator_Deallocate`?"
  );
  assert(
    a_Count > 0,
    L"`a_Count` being 0 makes `a_Size` equal to 0. Perhaps, you've meant to "
    L"use `CObjectWorldAllocator_Deallocate`?"
  );
  assert(a_AddressOut != NULL, L"`a_AddressOut` cannot be null.");
  uint64_t l_ChunkInnerSize = a_Size * a_Count;
  uint64_t l_ChunkSize = sizeof(CObjectWorldAllocatorChunk) + l_ChunkInnerSize;
  CObjectWorldAllocatorChunk *l_Chunk = NULL;
  uint64_t l_Alignment = a_Alignment == 0 ? alignof(uint64_t) : a_Alignment;
  if(a_Allocator->m_Kind == k_AllocatorKind_Auto)
  {
    l_Chunk = (CObjectWorldAllocatorChunk *)
#if defined(_WIN32) || defined(_WIN64)
      _aligned_malloc(l_ChunkSize, l_Alignment)
#elif defined(__linux__)
      aligned_alloc(l_Alignment, l_ChunkSize)
#endif
      ;
  }
  else if(a_Allocator->m_Kind == k_AllocatorKind_Arena)
  {
    a_Allocator->m_ArenaSize += l_ChunkSize;
    uint64_t l_SizePadding = -(uint64_t)a_Allocator->m_Arena & (l_Alignment - 1);
    uint64_t l_SizeCommitted = a_Allocator->m_ArenaCommit - a_Allocator->m_Arena;
    uint64_t l_Size = a_Size + sizeof(CObjectWorldAllocatorChunk);
    if(a_Count > (l_SizeCommitted - l_SizePadding) / l_Size)
    {
      uint64_t l_Reserved = a_Allocator->m_ArenaEnd - a_Allocator->m_Arena;
      if(a_Count > (l_Reserved - l_SizePadding) / l_Size) { return; }
      uint64_t l_SizeNeeded = l_ChunkSize + l_SizePadding - l_SizeCommitted;
      l_SizeNeeded += -l_SizeNeeded & (c_CObjectWorldAllocator_PageSize - 1);
      bool l_CommitResult =
#if defined(_WIN32) || defined(_WIN64)
        VirtualAlloc(a_Allocator->m_ArenaCommit, l_SizeNeeded, MEM_COMMIT, PAGE_READWRITE)
#elif defined(__linux__)
        mprotect(a_Allocator->m_ArenaCommit, l_SizeNeeded, PROT_READ | PROT_WRITE)
#endif
        ;
      assert(l_CommitResult, L"Could not commit %llu bytes of memory.", l_SizeNeeded);
      a_Allocator->m_ArenaCommit += l_SizeNeeded;
      a_Allocator->m_ArenaCapacity += l_SizeNeeded;
    }
    l_Chunk = (CObjectWorldAllocatorChunk *)(a_Allocator->m_Arena + l_SizePadding);
    l_Chunk->m_Size = l_ChunkInnerSize;
    l_Chunk->m_Alignment = l_Alignment;
    a_Allocator->m_Arena += l_SizePadding + l_ChunkSize;
  }
  assert(
    l_Chunk != NULL,
    L"Could not allocate %llu-byte aligned %llu bytes of memory (%llu times "
    L"%llu bytes requested, plus %llu bytes of overhead).",
    l_Alignment,
    l_ChunkSize,
    a_Size,
    a_Count,
    sizeof(CObjectWorldAllocatorChunk)
  );
  memset(l_Chunk, 0, l_ChunkSize);
  *a_AddressOut = l_Chunk->m_Inner;
}

void
CObjectWorldAllocator_Reallocate(
  CObjectWorldAllocator *a_Allocator,
  void *a_Address,
  uint64_t a_Alignment,
  uint64_t a_Size,
  uint64_t a_Count,
  void **a_AddressOut
)
{
  assert(a_Allocator != NULL);
  assert(a_Address != NULL, L"`a_Address` cannot be null.");
  assert(
    a_Size > 0,
    L"`a_Size` cannot be 0. Perhaps, you've meant to use "
    L"`CObjectWorldAllocator_Deallocate`?"
  );
  assert(
    a_Count > 0,
    L"`a_Count` being 0 makes `a_Size` equal to 0. Perhaps, you've meant to "
    L"use `CObjectWorldAllocator_Deallocate`?"
  );
  assert(a_Alignment > 0, L"`a_Alignment` cannot be 0.");
  assert(a_AddressOut != NULL, L"`a_AddressOut` cannot be null.");
  CObjectWorldAllocatorChunk *l_Chunk
    = (CObjectWorldAllocatorChunk *)((uint8_t *)a_Address - sizeof(CObjectWorldAllocatorChunk));
  uint64_t l_ChunkInnerSize = a_Size * a_Count;
  uint64_t l_ChunkSize = sizeof(CObjectWorldAllocatorChunk) + l_ChunkInnerSize;
  CObjectWorldAllocatorChunk *l_Chunk_ = NULL;
  uint64_t l_Alignment = a_Alignment == 0 ? alignof(uint64_t) : a_Alignment;
  if(a_Allocator->m_Kind == k_AllocatorKind_Auto)
  {
    l_Chunk_ = (CObjectWorldAllocatorChunk *)realloc(a_Address, l_ChunkSize);
  }
  else if(a_Allocator->m_Kind == k_AllocatorKind_Arena)
  {
    // If a_Chunk is the last chunk in the arena, bump it, otherwise allocate a
    // new one.
    if(a_Allocator->m_ArenaCommit - l_Chunk->m_Size == l_Chunk->m_Inner)
    {
      uint64_t l_ChunkSizeDifference
        = l_ChunkSize - (sizeof(CObjectWorldAllocatorChunk) + l_Chunk->m_Size);
      a_Allocator->m_ArenaSize += l_ChunkSizeDifference;
      uint8_t *l_ChunkEnd
        = (uint8_t *)l_Chunk + sizeof(CObjectWorldAllocatorChunk) + l_Chunk->m_Size;
      uint8_t *l_ChunkEnd_ = l_ChunkEnd + l_ChunkSizeDifference;
      if(l_ChunkEnd_ > a_Allocator->m_ArenaCommit)
      {
        uint64_t l_SizeAdditional = l_ChunkEnd_ - a_Allocator->m_ArenaCommit;
        l_SizeAdditional += -l_SizeAdditional & (c_CObjectWorldAllocator_PageSize - 1);
        bool l_CommitResult =
#if defined(_WIN32) || defined(_WIN64)
          VirtualAlloc(a_Allocator->m_ArenaCommit, l_SizeAdditional, MEM_COMMIT, PAGE_READWRITE)
#elif defined(__linux__)
          mprotect(a_Allocator->m_ArenaCommit, l_SizeAdditional, PROT_READ | PROT_WRITE)
#endif
          ;
        assert(l_CommitResult, L"Could not commit %llu bytes of memory.", l_SizeAdditional);
        a_Allocator->m_ArenaCommit += l_SizeAdditional;
        a_Allocator->m_ArenaCapacity += l_SizeAdditional;
      }
      a_Allocator->m_Arena += l_ChunkSizeDifference;
      l_Chunk->m_Size = l_ChunkInnerSize;
      l_Chunk->m_Alignment = l_Alignment;
      l_Chunk_ = l_Chunk;
    }
    else
    {
      void *l_Address;
      CObjectWorldAllocator_Allocate(a_Allocator, a_Alignment, a_Size, a_Count, &l_Address);
      l_Chunk_ = (CObjectWorldAllocatorChunk *)((uint8_t *)l_Address
                                                - sizeof(CObjectWorldAllocatorChunk));
      memcpy(
        l_Chunk_->m_Inner,
        a_Address,
        l_Chunk->m_Size < l_ChunkInnerSize ? l_Chunk->m_Size : l_ChunkInnerSize
      );
    }
  }
  assert(
    l_Chunk_ != NULL,
    L"Could not reallocate %llu-byte aligned %llu bytes of memory (%llu "
    L"times "
    L"%llu bytes requested, plus %llu bytes of overhead).",
    a_Alignment,
    l_ChunkSize,
    a_Size,
    a_Count,
    sizeof(CObjectWorldAllocatorChunk)
  );
  *a_AddressOut = l_Chunk_->m_Inner;
}

void
CObjectWorldAllocator_Deallocate(
  CObjectWorldAllocator *a_Allocator,
  void **a_Address
)
{
  assert(a_Allocator != NULL);
  assert(a_Address != NULL, L"`a_Address` cannot be null.");
  assert(*a_Address != NULL, L"`a_Address` cannot be null.");
  void *l_Address = *a_Address;
  if(a_Allocator->m_Kind == k_AllocatorKind_Auto) { free(*a_Address); }
  else if(a_Allocator->m_Kind == k_AllocatorKind_Arena)
  {
    CObjectWorldAllocatorChunk *l_Chunk
      = (CObjectWorldAllocatorChunk *)((uint8_t *)l_Address - sizeof(CObjectWorldAllocatorChunk));
    uint64_t l_ChunkInnerSize = l_Chunk->m_Size;
    uint64_t l_ChunkSize = sizeof(CObjectWorldAllocatorChunk) + l_ChunkInnerSize;
    a_Allocator->m_ArenaSize -= l_ChunkSize;
    memset(l_Chunk->m_Inner, 0, l_Chunk->m_Size);
    memset(l_Chunk, 0, sizeof(CObjectWorldAllocatorChunk));
    uint8_t *l_ChunkEnd
      = (uint8_t *)l_Chunk + sizeof(CObjectWorldAllocatorChunk) + l_ChunkInnerSize;
    if(l_ChunkEnd == a_Allocator->m_Arena)
    {
      a_Allocator->m_Arena = (uint8_t *)l_Chunk;
      uint64_t l_CommittedSize = a_Allocator->m_ArenaCommit - a_Allocator->m_Arena;
      if(l_CommittedSize >= c_CObjectWorldAllocator_PageSize)
      {
        uint64_t l_UncommitCount = l_CommittedSize / c_CObjectWorldAllocator_PageSize;
        uint64_t l_UncommitSize = l_UncommitCount * c_CObjectWorldAllocator_PageSize;
        uint32_t l_UncommitResult =
#if defined(_WIN32) || defined(_WIN64)
          VirtualFree(a_Allocator->m_Arena, l_UncommitSize, MEM_DECOMMIT)
#elif defined(__linux__)
          mprotect(a_Allocator->m_Arena, l_UncommitSize, PROT_NONE)
#endif
          ;
        assert(
#if defined(_WIN32) || defined(_WIN64)
          l_UncommitResult == 0,
#elif defined(__linux__)
          l_UncommitResult != 0,
#endif
          L"Could not uncommit %llu bytes of memory.",
          l_UncommitSize
        );
        a_Allocator->m_ArenaCommit -= l_UncommitSize;
        a_Allocator->m_ArenaCapacity -= l_UncommitSize;
      }
    }
  }
  *a_Address = NULL;
}

void
CObjectWorldAllocator_Free(
  CObjectWorldAllocator *a_Allocator
)
{
  assert(a_Allocator != NULL);

  if(a_Allocator->m_Kind == k_AllocatorKind_Arena)
  {
    uint32_t l_FreeResult =
#if defined(_WIN32) || defined(_WIN64)
      VirtualFree(a_Allocator->m_Arena, 0, MEM_RELEASE)
#elif defined(__linux__)
      munmap(a_Allocator->m_Arena, a_Allocator->m_ArenaEnd - a_Allocator->m_Arena)
#endif
      ;
    assert(
#if defined(_WIN32) || defined(_WIN64)
      l_FreeResult == 0,
#elif defined(__linux__)
      l_FreeResult != 0,
#endif
      L"Could not free %llu bytes memory.",
      a_Allocator->m_ArenaCapacity
    );
    a_Allocator->m_Arena = NULL;
    a_Allocator->m_ArenaCommit = NULL;
    a_Allocator->m_ArenaEnd = NULL;
  }
}

void
CObjectWorld_New(
  CObjectWorld *a_World,
  CObjectWorldAllocatorKind a_Kind,
  ...
)
{
  assert(a_World != NULL, "World is null");
  memset(a_World, 0, sizeof(CObjectWorld));
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
  assert(a_World != NULL);
  if(a_World->m_Allocator.m_Kind == k_AllocatorKind_Arena)
  {
    CObjectWorldAllocator_Free(&a_World->m_Allocator);
  }
  memset(a_World, 0, sizeof(CObjectWorld));
}
