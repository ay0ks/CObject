#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#include <sodium/crypto_shorthash.h>
#include <sodium/crypto_shorthash_siphash24.h>

typedef enum CObjectType : uint8_t {
  k_ObjectBoolean = 1,
  k_ObjectInteger,
  k_ObjectFloating,
  k_ObjectString,
  k_ObjectPair,
  k_ObjectList,
  k_ObjectDictionary,
  k_ObjectAny
} CObjectType;

typedef enum CObjectIntegerSignedness : uint8_t {
  k_IntegerSigned = 0,
  k_IntegerUnsigned = 1
} CObjectIntegerSignedness;

typedef enum CObjectIntegerSize : uint8_t {
  k_Integer8 = 0,
  k_Integer16 = 1,
  k_Integer32 = 2,
  k_Integer64 = 3
} CObjectIntegerSize;

typedef enum CObjectFloatingSize : uint8_t {
  k_Floating32 = 0,
  k_Floating64 = 1,
  k_Floating80 = 2
} CObjectFloatingSize;

typedef enum CObjectStringComparison : uint8_t {
  k_CObjectStringComparisonLessThan,
  k_CObjectStringComparisonEqual,
  k_CObjectStringComparisonGreaterThan
} CObjectStringComparison;

typedef struct CObject {
  CObjectType m_Type;

  union {
    bool m_Boolean;

    struct {
      CObjectIntegerSignedness m_Signedness;
      CObjectIntegerSize m_Size;

      union {
        int8_t m_Signed8;
        int16_t m_Signed16;
        int32_t m_Signed32;
        int64_t m_Signed64;
        uint8_t m_Unsigned8;
        uint16_t m_Unsigned16;
        uint32_t m_Unsigned32;
        uint64_t m_Unsigned64;
      } u_Integer;
    } u_Integer;

    struct {
      CObjectFloatingSize m_Size;

      union {
        float m_Floating32;
        double m_Floating64;
        long double m_Floating80;
      } u_Floating;
    } u_Floating;

    struct {
      uint64_t m_Size, m_Capacity;
      wchar_t *m_String;
    } u_String;

    struct {
      CObjectType m_LeftType, m_RightType;
      struct CObject *m_Left, *m_Right;
    } u_Pair;

    struct {
      CObjectType m_ItemType;
      uint64_t m_ItemCount, m_ItemCapacity;
      struct CObject **m_Items;
    } u_List;

    struct {
      CObjectType m_PairLeftType, m_PairRightType;
      uint64_t m_PairCount, m_PairCapacity;
      struct CObject *m_Pairs;
    } u_Dictionary;
  } m_Value;
} CObject;

void CObject_Initialize();

void CObject_GetType(CObject *a_Object, CObjectType *a_Type);

void CObjectList_GetAt(CObject *a_Object, uint64_t a_Index, CObject **a_Value);

void CObject_GetId(CObject *a_Object, uint64_t *a_Id);

void CObject_GetIdReasonable(CObject *a_Object, uint64_t *a_Id);

void CObject_Free(CObject *a_Object);

void CObjectBoolean_New(bool a_Value, CObject **a_Object);

void CObjectBoolean_NewFrom(CObject *a_Value, CObject **a_Object);

void CObjectBoolean_GetValue(CObject *a_Object, bool *a_Value);

void CObjectBoolean_SetValue(CObject *a_Object, bool a_Value);

void CObjectBoolean_Free(CObject *a_Object);

void CObjectInteger_New(CObjectIntegerSignedness a_Signedness,
                        CObjectIntegerSize a_Size, CObject **a_Object, ...);

void CObjectInteger_NewFrom(CObject *a_Value, CObject **a_Object);

void CObjectInteger_GetSignedness(CObject *a_Object,
                                  CObjectIntegerSignedness *a_Signedness);

void CObjectInteger_GetSize(CObject *a_Object, CObjectIntegerSize *a_Size);

void CObjectInteger_GetValue(CObject *a_Object, ...);

void CObjectInteget_SetValue(CObject *a_Object, ...);

void CObjectInteger_Free(CObject *a_Object);

void CObjectFloating_New(CObjectFloatingSize a_Size, CObject **a_Object, ...);

void CObjectFloating_NewFrom(CObject *a_Value, CObject **a_Object);

void CObjectFloating_GetSize(CObject *a_Object, CObjectFloatingSize *a_Size);

void CObjectFloating_GetValue(CObject *a_Object, ...);

void CObjectFloating_SetValue(CObject *a_Object, ...);

void CObjectFloating_Free(CObject *a_Object);

void CObjectString_New(uint64_t a_Length, wchar_t *a_String,
                       CObject **a_Object);

void CObjectString_NewFrom(CObject *a_Value, CObject **a_Object);

void CObjectString_GetAt(CObject *a_Object, uint64_t a_Index, wchar_t *a_Value);

void CObjectString_GetFirst(CObject *a_Object, wchar_t *a_Value);

void CObjectString_GetLast(CObject *a_Object, wchar_t *a_Value);

void CObjectString_GetSize(CObject *a_Object, uint64_t *a_Size);

void CObjectString_GetCapacity(CObject *a_Object, uint64_t *a_Capacity);

void CObjectString_IsEmpty(CObject *a_Object, bool *a_IsEmpty);

void CObjectString_GetStorage(CObject *a_Object, wchar_t **a_String);

void CObjectString_GetStorageEnd(CObject *a_Object, wchar_t **a_String);

void CObjectString_Shrink(CObject *a_Object, uint64_t a_Size);

void CObjectString_Grow(CObject *a_Object, uint64_t a_Size);

void CObjectString_Fit(CObject *a_Object);

void CObjectString_Clear(CObject *a_Object);

void CObjectString_InsertAt(CObject *a_Object, uint64_t a_Index,
                            CObject *a_Value);

void CObjectString_RemoveAt(CObject *a_Object, uint64_t a_Index,
                            uint64_t a_Size);

void CObjectString_PushBack(CObject *a_Object, CObject *a_Value);

void CObjectString_PushFront(CObject *a_Object, CObject *a_Value);

void CObjectString_PopBack(CObject *a_Object, uint64_t a_Size);

void CObjectString_PopFront(CObject *a_Object, uint64_t a_Size);

void CObjectString_FindFirst(CObject *a_Object, CObject *a_Value,
                             uint64_t a_Start, bool *a_Found,
                             uint64_t *a_Index);

void CObjectString_FindLast(CObject *a_Object, CObject *a_Value,
                            uint64_t a_Start, bool *a_Found, uint64_t *a_Index);

void CObjectString_Replace(CObject *a_Object, CObject *a_What, CObject *a_With);

void CObjectString_Compare(CObject *a_Object1, CObject *a_Object2,
                           CObjectStringComparison *a_Comparison);

void CObjectString_StartsWith(CObject *a_Object, CObject *a_Value,
                              bool *a_StartsWith);

void CObjectString_EndsWith(CObject *a_Object, CObject *a_Value,
                            bool *a_EndsWith);

void CObjectString_Contains(CObject *a_Object, CObject *a_Value,
                            bool *a_Contains);

CObject *CObjectString_Substring(CObject *a_Object, uint64_t a_Start,
                                 uint64_t a_End);

void CObjectList_New(
    // NOLINTBEGIN(bugprone-easily-swappable-parameters)
    CObjectType a_ItemType, uint64_t a_ItemCount,
    // NOLINTEND(bugprone-easily-swappable-parameters)
    CObject **a_Object, ...);

void CObjectList_PushBack(CObject *a_Object, uint64_t a_Count, ...);

void CObjectString_Split(CObject *a_Object, CObject *a_Value, CObject **a_List);

void CObjectString_Extend(CObject *a_Object, uint64_t a_Index,
                          CObject *a_Value);

void CObjectString_Swap(CObject *a_Object, uint64_t a_Index1,
                        uint64_t a_Index2);

void CObjectString_Free(CObject *a_Object);

void CObjectPair_New(CObject *a_Left, CObject *a_Right, CObject **a_Object);

void CObjectPair_NewFrom(CObject *a_Value, CObject **a_Object);

void CObjectPair_GetValue(CObject *a_Object,
                          // NOLINTBEGIN(bugprone-easily-swappable-parameters)
                          CObject **a_Left, CObject **a_Right
                          // NOLINTEND(bugprone-easily-swappable-parameters)
);

void CObjectPair_SetValue(CObject *a_Object, CObject *a_Left, CObject *a_Right);

void CObjectPair_Free(CObject *a_Object);

void CObjectList_New(
    // NOLINTBEGIN(bugprone-easily-swappable-parameters)
    CObjectType a_ItemType, uint64_t a_ItemCount,
    // NOLINTEND(bugprone-easily-swappable-parameters)
    CObject **a_Object, ...);

void CObjectList_NewFrom(CObject *a_Value, CObject **a_Object);

void CObjectList_GetAt(CObject *a_Object, uint64_t a_Index, CObject **a_Value);

void CObjectList_GetFirst(CObject *a_Object, CObject **a_Value);

void CObjectList_GetLast(CObject *a_Object, CObject **a_Value);

void CObjectList_GetIndex(CObject *a_Object, CObject *a_Item, int64_t *a_Index);

void CObjectList_GetSize(CObject *a_Object, uint64_t *a_Size);

void CObjectList_GetCapacity(CObject *a_Object, uint64_t *a_Capacity);

void CObjectList_GetStorage(CObject *a_Object, CObject ***a_Storage);

void CObjectList_GetStorageEnd(CObject *a_Object, CObject ***a_StorageEnd);

void CObjectList_GetItemType(CObject *a_Object, CObjectType *a_ItemType);

void CObjectList_Shrink(CObject *a_Object, uint64_t a_Size);

void CObjectList_Grow(CObject *a_Object, uint64_t a_Size);

void CObjectList_Clear(CObject *a_Object);

void CObjectList_Fit(CObject *a_Object);

void CObjectList_InsertAt(CObject *a_Object, uint64_t a_Index, uint64_t a_Count,
                          ...);

void CObjectList_RemoveAt(CObject *a_Object, uint64_t a_Index, uint64_t a_Count,
                          ...);

void CObjectList_PushBack(CObject *a_Object, uint64_t a_Count, ...);

void CObjectList_PushFront(CObject *a_Object, uint64_t a_Count, ...);

void CObjectList_PopBack(CObject *a_Object, uint64_t a_Count, ...);

void CObjectList_PopFront(CObject *a_Object, uint64_t a_Count, ...);

void CObjectList_Swap(CObject *a_Object, uint64_t a_Index1, uint64_t a_Index2);

void CObjectList_Free(CObject *a_Object);

void CObjectDictionary_New(
    // NOLINTBEGIN(bugprone-easily-swappable-parameters)
    CObjectType a_LeftType, CObjectType a_RightType, uint64_t a_PairCount,
    CObject **a_Object,
    // NOLINTEND(bugprone-easily-swappable-parameters)
    ...);

void CObjectDictionary_NewFrom(CObject *a_Value, CObject **a_Object);

void CObjectDictionary_Free(CObject *a_Object);

void CObject_Free(CObject *a_Object);