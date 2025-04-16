#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#include <sodium/crypto_shorthash.h>
#include <sodium/crypto_shorthash_siphash24.h>

typedef enum CObjectWorldAllocatorKind: uint8_t
{
  /**
   * Use allocator linked with the executable, or loaded with `LD_PRELOAD`.
   */
  k_AllocatorKind_Auto,
  /**
   * Use the arena allocator.
   */
  k_AllocatorKind_Arena
} CObjectWorldAllocatorKind;

typedef struct CObjectWorldAllocatorChunkHeader
{
  uint64_t m_OffsetBegin, m_OffsetEnd;
} CObjectWorldAllocatorChunk;

typedef struct CObjectWorldAllocator
{
  CObjectWorldAllocatorKind m_Kind;

  char *m_Base, *m_BaseCommit, *m_BaseEnd;
  struct
  {
    uint64_t m_Initial, m_Maximum, m_Current;
    float m_ResizeFactor;
  } m_BaseSize;
} CObjectWorldAllocator;

const uint64_t c_CObjectWorldAllocator_PageSize = 1 << 26;

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

typedef struct CObjectWorld
{
  uint8_t m_Secret[crypto_shorthash_KEYBYTES];

  CObjectWorldAllocator m_Allocator;
} CObjectWorld;

void
CObjectWorld_New(
  CObjectWorld *a_World,
  CObjectWorldAllocatorKind a_Kind,
  ...
);

void
CObjectWorld_Free(CObjectWorld *a_World);
