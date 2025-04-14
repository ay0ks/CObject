#include <assert.h>
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

uint8_t g_CObject_GetId_Key[crypto_shorthash_KEYBYTES];

typedef enum CObjectType : uint8_t
{
  k_ObjectBoolean = 1,
  k_ObjectInteger,
  k_ObjectFloating,
  k_ObjectString,
  k_ObjectPair,
  k_ObjectList,
  k_ObjectDictionary,
  k_ObjectAny
} CObjectType;

typedef enum CObjectIntegerSignedness : uint8_t
{
  k_IntegerSigned   = 0,
  k_IntegerUnsigned = 1
} CObjectIntegerSignedness;

typedef enum CObjectIntegerSize : uint8_t
{
  k_Integer8  = 0,
  k_Integer16 = 1,
  k_Integer32 = 2,
  k_Integer64 = 3
} CObjectIntegerSize;

typedef enum CObjectFloatingSize : uint8_t
{
  k_Floating32 = 0,
  k_Floating64 = 1,
  k_Floating80 = 2
} CObjectFloatingSize;

typedef enum CObjectStringComparison : uint8_t
{
  k_CObjectStringComparisonLessThan,
  k_CObjectStringComparisonEqual,
  k_CObjectStringComparisonGreaterThan
} CObjectStringComparison;

typedef struct CObject
{
  CObjectType m_Type;

  union
  {
    bool m_Boolean;

    struct
    {
      CObjectIntegerSignedness m_Signedness;
      CObjectIntegerSize       m_Size;

      union
      {
        int8_t   m_Signed8;
        int16_t  m_Signed16;
        int32_t  m_Signed32;
        int64_t  m_Signed64;
        uint8_t  m_Unsigned8;
        uint16_t m_Unsigned16;
        uint32_t m_Unsigned32;
        uint64_t m_Unsigned64;
      } u_Integer;
    } u_Integer;

    struct
    {
      CObjectFloatingSize m_Size;

      union
      {
        float       m_Floating32;
        double      m_Floating64;
        long double m_Floating80;
      } u_Floating;
    } u_Floating;

    struct
    {
      uint64_t m_Size, m_Capacity;
      wchar_t *m_String;
    } u_String;

    struct
    {
      CObjectType     m_LeftType, m_RightType;
      struct CObject *m_Left, *m_Right;
    } u_Pair;

    struct
    {
      CObjectType      m_ItemType;
      uint64_t         m_ItemCount, m_ItemCapacity;
      struct CObject **m_Items;
    } u_List;

    struct
    {
      CObjectType     m_PairLeftType, m_PairRightType;
      uint64_t        m_PairCount, m_PairCapacity;
      struct CObject *m_Pairs;
    } u_Dictionary;
  } m_Value;
} CObject;

void
CObject_GetType(
  CObject     *a_Object,
  CObjectType *a_Type
)
{
  assert(a_Object != NULL);
  assert(a_Type != NULL);
  *a_Type = a_Object->m_Type;
}

void
CObjectList_GetAt(
  CObject  *a_Object,
  uint64_t  a_Index,
  CObject **a_Value
);

void
CObject_GetId(
  CObject  *a_Object,
  uint64_t *a_Id
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type != k_ObjectAny);
  assert(a_Id != NULL);
  uint64_t l_Id = 0;
  uint8_t  l_Hash[crypto_shorthash_BYTES];
  uint8_t  l_Type    = (uint8_t) a_Object->m_Type;
  uint64_t l_Address = (uint64_t) a_Object;
  crypto_shorthash(l_Hash, (const uint8_t *) &l_Type, sizeof(l_Type), g_CObject_GetId_Key);
  l_Id = *(uint64_t *) l_Hash;
  crypto_shorthash(l_Hash, (const uint8_t *) &l_Address, sizeof(l_Address), g_CObject_GetId_Key);
  l_Id  ^= *(uint64_t *) l_Hash;
  *a_Id  = l_Id;
}

void
CObject_GetIdReasonable(
  CObject  *a_Object,
  uint64_t *a_Id
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type != k_ObjectAny);
  assert(a_Id != NULL);
  uint64_t l_Id = 0;
  uint8_t  l_Hash[crypto_shorthash_BYTES];
  uint8_t  l_Type = (uint8_t) a_Object->m_Type;
  crypto_shorthash(l_Hash, (const uint8_t *) &l_Type, sizeof(l_Type), g_CObject_GetId_Key);
  l_Id = *(uint64_t *) l_Hash;
  switch(a_Object->m_Type)
  {
    case k_ObjectBoolean :
    {
      l_Id ^= (uint64_t) a_Object->m_Value.m_Boolean;
      break;
    }
    case k_ObjectInteger :
    {
      l_Id ^= (uint64_t) a_Object->m_Value.u_Integer.m_Signedness;
      l_Id ^= (uint64_t) a_Object->m_Value.u_Integer.m_Size;
      crypto_shorthash(
        l_Hash,
        (const uint8_t *) &a_Object->m_Value.u_Integer.u_Integer,
        sizeof(a_Object->m_Value.u_Integer),
        g_CObject_GetId_Key
      );
      l_Id ^= *(uint64_t *) l_Hash;
      break;
    }
    case k_ObjectFloating :
    {
      l_Id ^= (uint64_t) a_Object->m_Value.u_Floating.m_Size;
      crypto_shorthash(
        l_Hash,
        (const uint8_t *) &a_Object->m_Value.u_Floating.u_Floating,
        sizeof(a_Object->m_Value.u_Floating),
        g_CObject_GetId_Key
      );
      l_Id ^= *(uint64_t *) l_Hash;
      break;
    }
    case k_ObjectString :
    {
      l_Id ^= (uint64_t) a_Object->m_Value.u_String.m_Size;
      l_Id ^= (uint64_t) a_Object->m_Value.u_String.m_Capacity;
      crypto_shorthash(
        l_Hash,
        (const uint8_t *) a_Object->m_Value.u_String.m_String,
        sizeof(wchar_t) * a_Object->m_Value.u_String.m_Capacity,
        g_CObject_GetId_Key
      );
      l_Id ^= *(uint64_t *) l_Hash;
      break;
    }
    case k_ObjectPair :
    {
      l_Id ^= (uint64_t) a_Object->m_Value.u_Pair.m_LeftType;
      l_Id ^= (uint64_t) a_Object->m_Value.u_Pair.m_RightType;
      uint64_t l_Id_;
      CObject_GetIdReasonable(a_Object->m_Value.u_Pair.m_Left, &l_Id_);
      l_Id ^= l_Id_;
      CObject_GetIdReasonable(a_Object->m_Value.u_Pair.m_Right, &l_Id_);
      l_Id ^= l_Id_;
      break;
    }
    case k_ObjectList :
    {
      l_Id ^= (uint64_t) a_Object->m_Value.u_List.m_ItemType;
      l_Id ^= (uint64_t) a_Object->m_Value.u_List.m_ItemCount;
      l_Id ^= (uint64_t) a_Object->m_Value.u_List.m_ItemCapacity;
      for(uint64_t l_Index = 0; l_Index < a_Object->m_Value.u_List.m_ItemCount; l_Index++)
      {
        uint64_t l_Id_;
        CObject_GetIdReasonable(a_Object->m_Value.u_List.m_Items[l_Index], &l_Id_);
        l_Id ^= l_Id_;
      }
      break;
    }
    case k_ObjectDictionary :
    {
      l_Id ^= (uint64_t) a_Object->m_Value.u_Dictionary.m_PairLeftType;
      l_Id ^= (uint64_t) a_Object->m_Value.u_Dictionary.m_PairRightType;
      l_Id ^= (uint64_t) a_Object->m_Value.u_Dictionary.m_PairCount;
      l_Id ^= (uint64_t) a_Object->m_Value.u_Dictionary.m_PairCapacity;
      for(uint64_t l_Index = 0; l_Index < a_Object->m_Value.u_Dictionary.m_PairCount; l_Index++)
      {
        uint64_t l_Id_;
        CObject_GetIdReasonable(&a_Object->m_Value.u_Dictionary.m_Pairs[l_Index], &l_Id_);
        l_Id ^= l_Id_;
      }
      break;
    }
    default :
    {
      assert(false);
      break;
    }
  }
  *a_Id = l_Id;
}

void
CObject_Free(CObject *a_Object);

void
CObjectBoolean_New(
  bool      a_Value,
  CObject **a_Object
)
{
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type            = k_ObjectBoolean;
  l_Object->m_Value.m_Boolean = a_Value;
  *a_Object                   = l_Object;
}

void
CObjectBoolean_NewFrom(
  CObject  *a_Value,
  CObject **a_Object
)
{
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectBoolean);
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type            = k_ObjectBoolean;
  l_Object->m_Value.m_Boolean = a_Value->m_Value.m_Boolean;
  *a_Object                   = l_Object;
}

void
CObjectBoolean_GetValue(
  CObject *a_Object,
  bool    *a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectBoolean);
  assert(a_Value != NULL);
  *a_Value = a_Object->m_Value.m_Boolean;
}

void
CObjectBoolean_SetValue(
  CObject *a_Object,
  bool     a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectBoolean);
  a_Object->m_Value.m_Boolean = a_Value;
}

void
CObjectBoolean_Free(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectBoolean);
  free(a_Object);
}

void
CObjectInteger_New(
  CObjectIntegerSignedness a_Signedness,
  CObjectIntegerSize       a_Size,
  CObject                **a_Object,
  ...
)
{
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  va_list l_Args;
  va_start(l_Args, a_Object);
  l_Object->m_Type                         = k_ObjectInteger;
  l_Object->m_Value.u_Integer.m_Signedness = a_Signedness;
  l_Object->m_Value.u_Integer.m_Size       = a_Size;
  switch(a_Size)
  {
    case k_Integer8 :
    {
      if(a_Signedness == k_IntegerSigned)
      {
        l_Object->m_Value.u_Integer.u_Integer.m_Signed8 = va_arg(l_Args, int8_t);
      }
      else
      {
        l_Object->m_Value.u_Integer.u_Integer.m_Unsigned8 = va_arg(l_Args, uint8_t);
      }
      break;
    }
    case k_Integer16 :
    {
      if(a_Signedness == k_IntegerSigned)
      {
        l_Object->m_Value.u_Integer.u_Integer.m_Signed16 = va_arg(l_Args, int16_t);
      }
      else
      {
        l_Object->m_Value.u_Integer.u_Integer.m_Unsigned16 = va_arg(l_Args, uint16_t);
      }
      break;
    }
    case k_Integer32 :
    {
      if(a_Signedness == k_IntegerSigned)
      {
        l_Object->m_Value.u_Integer.u_Integer.m_Signed32 = va_arg(l_Args, int32_t);
      }
      else
      {
        l_Object->m_Value.u_Integer.u_Integer.m_Unsigned32 = va_arg(l_Args, uint32_t);
      }
      break;
    }
    case k_Integer64 :
    {
      if(a_Signedness == k_IntegerSigned)
      {
        l_Object->m_Value.u_Integer.u_Integer.m_Signed64 = va_arg(l_Args, int64_t);
      }
      else
      {
        l_Object->m_Value.u_Integer.u_Integer.m_Unsigned64 = va_arg(l_Args, uint64_t);
      }
    }
  }
  va_end(l_Args);
  *a_Object = l_Object;
}

void
CObjectInteger_NewFrom(
  CObject  *a_Value,
  CObject **a_Object
)
{
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectInteger);
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type                         = k_ObjectInteger;
  l_Object->m_Value.u_Integer.m_Signedness = a_Value->m_Value.u_Integer.m_Signedness;
  l_Object->m_Value.u_Integer.m_Size       = a_Value->m_Value.u_Integer.m_Size;
  memcpy(&l_Object->m_Value.u_Integer.u_Integer, &a_Value->m_Value.u_Integer.u_Integer, sizeof(a_Value->m_Value));
  *a_Object = l_Object;
}

void
CObjectInteger_GetSignedness(
  CObject                  *a_Object,
  CObjectIntegerSignedness *a_Signedness
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectInteger);
  assert(a_Signedness != NULL);
  *a_Signedness = a_Object->m_Value.u_Integer.m_Signedness;
}

void
CObjectInteger_GetSize(
  CObject            *a_Object,
  CObjectIntegerSize *a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectInteger);
  assert(a_Size != NULL);
  *a_Size = a_Object->m_Value.u_Integer.m_Size;
}

void
CObjectInteger_GetValue(
  CObject *a_Object,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectInteger);
  CObjectIntegerSignedness l_Signedness;
  CObjectInteger_GetSignedness(a_Object, &l_Signedness);
  CObjectIntegerSize l_Size;
  CObjectInteger_GetSize(a_Object, &l_Size);
  va_list l_Args;
  va_start(l_Args, a_Object);
  switch(l_Size)
  {
    case k_Integer8 :
    {
      if(l_Signedness == k_IntegerSigned)
      {
        int8_t *l_Value = va_arg(l_Args, int8_t *);
        *l_Value        = a_Object->m_Value.u_Integer.u_Integer.m_Signed8;
      }
      else
      {
        uint8_t *l_Value = va_arg(l_Args, uint8_t *);
        *l_Value         = a_Object->m_Value.u_Integer.u_Integer.m_Unsigned8;
      }
      break;
    }
    case k_Integer16 :
    {
      if(l_Signedness == k_IntegerSigned)
      {
        int16_t *l_Value = va_arg(l_Args, int16_t *);
        *l_Value         = a_Object->m_Value.u_Integer.u_Integer.m_Signed16;
      }
      else
      {
        uint16_t *l_Value = va_arg(l_Args, uint16_t *);
        *l_Value          = a_Object->m_Value.u_Integer.u_Integer.m_Unsigned16;
      }
      break;
    }
    case k_Integer32 :
    {
      if(l_Signedness == k_IntegerSigned)
      {
        int32_t *l_Value = va_arg(l_Args, int32_t *);
        *l_Value         = a_Object->m_Value.u_Integer.u_Integer.m_Signed32;
      }
      else
      {
        uint32_t *l_Value = va_arg(l_Args, uint32_t *);
        *l_Value          = a_Object->m_Value.u_Integer.u_Integer.m_Unsigned32;
      }
      break;
    }
    case k_Integer64 :
    {
      if(l_Signedness == k_IntegerSigned)
      {
        int64_t *l_Value = va_arg(l_Args, int64_t *);
        *l_Value         = a_Object->m_Value.u_Integer.u_Integer.m_Signed64;
      }
      else
      {
        uint64_t *l_Value = va_arg(l_Args, uint64_t *);
        *l_Value          = a_Object->m_Value.u_Integer.u_Integer.m_Unsigned64;
      }
      break;
    }
  }
  va_end(l_Args);
}

void
CObjectInteget_SetValue(
  CObject *a_Object,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectInteger);
  CObjectIntegerSignedness l_Signedness;
  CObjectInteger_GetSignedness(a_Object, &l_Signedness);
  CObjectIntegerSize l_Size;
  CObjectInteger_GetSize(a_Object, &l_Size);
  va_list l_Args;
  va_start(l_Args, a_Object);
  switch(l_Size)
  {
    case k_Integer8 :
    {
      if(l_Signedness == k_IntegerSigned)
      {
        int8_t *l_Value                                 = va_arg(l_Args, int8_t *);
        a_Object->m_Value.u_Integer.u_Integer.m_Signed8 = *l_Value;
      }
      else
      {
        uint8_t *l_Value                                  = va_arg(l_Args, uint8_t *);
        a_Object->m_Value.u_Integer.u_Integer.m_Unsigned8 = *l_Value;
      }
      break;
    }
    case k_Integer16 :
    {
      if(l_Signedness == k_IntegerSigned)
      {
        int16_t *l_Value                                 = va_arg(l_Args, int16_t *);
        a_Object->m_Value.u_Integer.u_Integer.m_Signed16 = *l_Value;
      }
      else
      {
        uint16_t *l_Value                                  = va_arg(l_Args, uint16_t *);
        a_Object->m_Value.u_Integer.u_Integer.m_Unsigned16 = *l_Value;
      }
      break;
    }
    case k_Integer32 :
    {
      if(l_Signedness == k_IntegerSigned)
      {
        int32_t *l_Value                                 = va_arg(l_Args, int32_t *);
        a_Object->m_Value.u_Integer.u_Integer.m_Signed32 = *l_Value;
      }
      else
      {
        uint32_t *l_Value                                  = va_arg(l_Args, uint32_t *);
        a_Object->m_Value.u_Integer.u_Integer.m_Unsigned32 = *l_Value;
      }
      break;
    }
    case k_Integer64 :
    {
      if(l_Signedness == k_IntegerSigned)
      {
        int64_t *l_Value                                 = va_arg(l_Args, int64_t *);
        a_Object->m_Value.u_Integer.u_Integer.m_Signed64 = *l_Value;
      }
      else
      {
        uint64_t *l_Value                                  = va_arg(l_Args, uint64_t *);
        a_Object->m_Value.u_Integer.u_Integer.m_Unsigned64 = *l_Value;
      }
      break;
    }
  }
  va_end(l_Args);
}

void
CObjectInteger_Free(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectInteger);
  free(a_Object);
}

void
CObjectFloating_New(
  CObjectFloatingSize a_Size,
  CObject           **a_Object,
  ...
)
{
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  va_list l_Args;
  va_start(l_Args, a_Object);
  l_Object->m_Type                    = k_ObjectFloating;
  l_Object->m_Value.u_Floating.m_Size = a_Size;
  switch(a_Size)
  {
    case k_Floating32 :
    {
      l_Object->m_Value.u_Floating.u_Floating.m_Floating32 = va_arg(l_Args, float);
      break;
    }
    case k_Floating64 :
    {
      l_Object->m_Value.u_Floating.u_Floating.m_Floating64 = va_arg(l_Args, double);
      break;
    }
    case k_Floating80 :
    {
      l_Object->m_Value.u_Floating.u_Floating.m_Floating80 = va_arg(l_Args, long double);
      break;
    }
  }
  va_end(l_Args);
  *a_Object = l_Object;
}

void
CObjectFloating_NewFrom(
  CObject  *a_Value,
  CObject **a_Object
)
{
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectFloating);
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type                    = k_ObjectFloating;
  l_Object->m_Value.u_Floating.m_Size = a_Value->m_Value.u_Floating.m_Size;
  memcpy(&l_Object->m_Value.u_Floating.u_Floating, &a_Value->m_Value.u_Floating.u_Floating, sizeof(a_Value->m_Value));
  *a_Object = l_Object;
}

void
CObjectFloating_GetSize(
  CObject             *a_Object,
  CObjectFloatingSize *a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectFloating);
  assert(a_Size != NULL);
  *a_Size = a_Object->m_Value.u_Floating.m_Size;
}

void
CObjectFloating_GetValue(
  CObject *a_Object,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectFloating);
  CObjectFloatingSize l_Size;
  CObjectFloating_GetSize(a_Object, &l_Size);
  va_list l_Args;
  va_start(l_Args, a_Object);
  switch(l_Size)
  {
    case k_Floating32 :
    {
      float *l_Value = va_arg(l_Args, float *);
      *l_Value       = a_Object->m_Value.u_Floating.u_Floating.m_Floating32;
      break;
    }
    case k_Floating64 :
    {
      double *l_Value = va_arg(l_Args, double *);
      *l_Value        = a_Object->m_Value.u_Floating.u_Floating.m_Floating64;
      break;
    }
    case k_Floating80 :
    {
      long double *l_Value = va_arg(l_Args, long double *);
      *l_Value             = a_Object->m_Value.u_Floating.u_Floating.m_Floating80;
      break;
    }
  }
  va_end(l_Args);
}

void
CObjectFloating_SetValue(
  CObject *a_Object,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectFloating);
  CObjectFloatingSize l_Size;
  CObjectFloating_GetSize(a_Object, &l_Size);
  va_list l_Args;
  va_start(l_Args, a_Object);
  switch(l_Size)
  {
    case k_Floating32 :
    {
      float *l_Value                                       = va_arg(l_Args, float *);
      a_Object->m_Value.u_Floating.u_Floating.m_Floating32 = *l_Value;
      break;
    }
    case k_Floating64 :
    {
      double *l_Value                                      = va_arg(l_Args, double *);
      a_Object->m_Value.u_Floating.u_Floating.m_Floating64 = *l_Value;
      break;
    }
    case k_Floating80 :
    {
      long double *l_Value                                 = va_arg(l_Args, long double *);
      a_Object->m_Value.u_Floating.u_Floating.m_Floating80 = *l_Value;
      break;
    }
  }
  va_end(l_Args);
}

void
CObjectFloating_Free(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectFloating);
  free(a_Object);
}

void
CObjectString_New(
  uint64_t  a_Length,
  wchar_t  *a_String,
  CObject **a_Object
)
{
  assert(a_String != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type                      = k_ObjectString;
  l_Object->m_Value.u_String.m_Size     = a_Length;
  l_Object->m_Value.u_String.m_Capacity = a_Length + 1;
  l_Object->m_Value.u_String.m_String   = malloc(sizeof(wchar_t) * l_Object->m_Value.u_String.m_Capacity);
  assert(l_Object->m_Value.u_String.m_String != NULL);
  wcscpy_s(l_Object->m_Value.u_String.m_String, l_Object->m_Value.u_String.m_Capacity, a_String);
  *a_Object = l_Object;
}

void
CObjectString_NewFrom(
  CObject  *a_Value,
  CObject **a_Object
)
{
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type                      = k_ObjectString;
  l_Object->m_Value.u_String.m_Size     = a_Value->m_Value.u_String.m_Size;
  l_Object->m_Value.u_String.m_Capacity = a_Value->m_Value.u_String.m_Capacity;
  l_Object->m_Value.u_String.m_String   = malloc(sizeof(wchar_t) * a_Value->m_Value.u_String.m_Capacity);
  assert(l_Object->m_Value.u_String.m_String != NULL);
  wcscpy_s(
    l_Object->m_Value.u_String.m_String, a_Value->m_Value.u_String.m_Capacity, a_Value->m_Value.u_String.m_String
  );
  *a_Object = l_Object;
}

void
CObjectString_GetAt(
  CObject *a_Object,
  uint64_t a_Index,
  wchar_t *a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Index < a_Object->m_Value.u_String.m_Size);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Value != NULL);
  if(a_Object->m_Value.u_String.m_Size == 0)
  {
    *a_Value = L'\0';
    return;
  }
  *a_Value = a_Object->m_Value.u_String.m_String[a_Index];
}

void
CObjectString_GetFirst(
  CObject *a_Object,
  wchar_t *a_Value
)
{
  CObjectString_GetAt(a_Object, 0, a_Value);
}

void
CObjectString_GetLast(
  CObject *a_Object,
  wchar_t *a_Value
)
{
  CObjectString_GetAt(a_Object, a_Object->m_Value.u_String.m_Size - 1, a_Value);
}

void
CObjectString_GetSize(
  CObject  *a_Object,
  uint64_t *a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Size != NULL);
  *a_Size = a_Object->m_Value.u_String.m_Size;
}

void
CObjectString_GetCapacity(
  CObject  *a_Object,
  uint64_t *a_Capacity
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Capacity != NULL);
  *a_Capacity = a_Object->m_Value.u_String.m_Capacity;
}

void
CObjectString_IsEmpty(
  CObject *a_Object,
  bool    *a_IsEmpty
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_IsEmpty != NULL);
  *a_IsEmpty = (a_Object->m_Value.u_String.m_Size == 0);
}

void
CObjectString_GetStorage(
  CObject  *a_Object,
  wchar_t **a_String
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_String != NULL);
  *a_String = a_Object->m_Value.u_String.m_String;
}

void
CObjectString_GetStorageEnd(
  CObject  *a_Object,
  wchar_t **a_String
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_String != NULL);
  *a_String = a_Object->m_Value.u_String.m_String + a_Object->m_Value.u_String.m_Size;
}

void
CObjectString_Shrink(
  CObject *a_Object,
  uint64_t a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  if(a_Size < a_Object->m_Value.u_String.m_Capacity)
  {
    if(a_Size < a_Object->m_Value.u_String.m_Size)
    {
      a_Object->m_Value.u_String.m_Size = a_Size;
    }
    a_Object->m_Value.u_String.m_Capacity = a_Size + 1;
    a_Object->m_Value.u_String.m_String   = (wchar_t *
    ) realloc(a_Object->m_Value.u_String.m_String, sizeof(wchar_t) * a_Object->m_Value.u_String.m_Capacity);
    assert(a_Object->m_Value.u_String.m_String != NULL);
  }
}

void
CObjectString_Grow(
  CObject *a_Object,
  uint64_t a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  if(a_Size > a_Object->m_Value.u_String.m_Capacity)
  {
    a_Object->m_Value.u_String.m_Capacity = a_Size + 1;
    a_Object->m_Value.u_String.m_String   = (wchar_t *
    ) realloc(a_Object->m_Value.u_String.m_String, sizeof(wchar_t) * a_Object->m_Value.u_String.m_Capacity);
    assert(a_Object->m_Value.u_String.m_String != NULL);
  }
}

void
CObjectString_Fit(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  if(a_Object->m_Value.u_String.m_Size < a_Object->m_Value.u_String.m_Capacity)
  {
    a_Object->m_Value.u_String.m_Capacity = a_Object->m_Value.u_String.m_Size + 1;
    a_Object->m_Value.u_String.m_String   = (wchar_t *
    ) realloc(a_Object->m_Value.u_String.m_String, sizeof(CObject) * a_Object->m_Value.u_String.m_Capacity);
  }
}

void
CObjectString_Clear(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  wmemset(a_Object->m_Value.u_String.m_String, 0, sizeof(wchar_t) * a_Object->m_Value.u_String.m_Capacity);
  a_Object->m_Value.u_String.m_Size = 0;
}

void
CObjectString_InsertAt(
  CObject *a_Object,
  uint64_t a_Index,
  CObject *a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Index < a_Object->m_Value.u_String.m_Size);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  uint64_t l_Size = a_Object->m_Value.u_String.m_Size + a_Value->m_Value.u_String.m_Size;
  CObjectString_Grow(a_Object, l_Size);
  wmemmove_s(
    &a_Object->m_Value.u_String.m_String[a_Index + a_Value->m_Value.u_String.m_Size],
    a_Object->m_Value.u_String.m_Capacity - (a_Index + a_Value->m_Value.u_String.m_Size),
    &a_Object->m_Value.u_String.m_String[a_Index],
    a_Object->m_Value.u_String.m_Capacity - a_Index
  );
  wmemcpy_s(
    &a_Object->m_Value.u_String.m_String[a_Index],
    a_Object->m_Value.u_String.m_Capacity - a_Index,
    a_Value->m_Value.u_String.m_String,
    a_Value->m_Value.u_String.m_Size
  );
  a_Object->m_Value.u_String.m_Size += a_Value->m_Value.u_String.m_Size;
}

void
CObjectString_RemoveAt(
  CObject *a_Object,
  uint64_t a_Index,
  uint64_t a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Index < a_Object->m_Value.u_String.m_Size);
  assert(a_Size > 0);
  assert(a_Index + a_Size <= a_Object->m_Value.u_String.m_Size);
  wmemmove_s(
    &a_Object->m_Value.u_String.m_String[a_Index],
    a_Object->m_Value.u_String.m_Capacity - a_Index,
    &a_Object->m_Value.u_String.m_String[a_Index + a_Size],
    a_Object->m_Value.u_String.m_Capacity - (a_Index + a_Size)
  );
  a_Object->m_Value.u_String.m_Size -= a_Size;
  CObjectString_Shrink(a_Object, a_Object->m_Value.u_String.m_Size);
}

void
CObjectString_PushBack(
  CObject *a_Object,
  CObject *a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  uint64_t l_Size = a_Object->m_Value.u_String.m_Size + a_Value->m_Value.u_String.m_Size;
  CObjectString_Grow(a_Object, l_Size);
  wmemcpy_s(
    &a_Object->m_Value.u_String.m_String[a_Object->m_Value.u_String.m_Size],
    a_Object->m_Value.u_String.m_Capacity - a_Object->m_Value.u_String.m_Size,
    a_Value->m_Value.u_String.m_String,
    a_Value->m_Value.u_String.m_Size
  );
  a_Object->m_Value.u_String.m_Size += a_Value->m_Value.u_String.m_Size;
}

void
CObjectString_PushFront(
  CObject *a_Object,
  CObject *a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  uint64_t l_Size = a_Object->m_Value.u_String.m_Size + a_Value->m_Value.u_String.m_Size;
  CObjectString_Grow(a_Object, l_Size);
  wmemmove_s(
    &a_Object->m_Value.u_String.m_String[a_Value->m_Value.u_String.m_Size],
    a_Object->m_Value.u_String.m_Capacity - a_Value->m_Value.u_String.m_Size,
    &a_Object->m_Value.u_String.m_String[0],
    a_Object->m_Value.u_String.m_Size
  );
  wmemcpy_s(
    &a_Object->m_Value.u_String.m_String[0],
    a_Object->m_Value.u_String.m_Capacity,
    a_Value->m_Value.u_String.m_String,
    a_Value->m_Value.u_String.m_Size
  );
  a_Object->m_Value.u_String.m_Size += a_Value->m_Value.u_String.m_Size;
}

void
CObjectString_PopBack(
  CObject *a_Object,
  uint64_t a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Size > 0);
  assert(a_Size <= a_Object->m_Value.u_String.m_Size);
  a_Object->m_Value.u_String.m_Size -= a_Size;
  wmemset(&a_Object->m_Value.u_String.m_String[a_Object->m_Value.u_String.m_Size], 0, sizeof(wchar_t) * a_Size);
  CObjectString_Shrink(a_Object, a_Object->m_Value.u_String.m_Size);
}

void
CObjectString_PopFront(
  CObject *a_Object,
  uint64_t a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Size > 0);
  assert(a_Size <= a_Object->m_Value.u_String.m_Size);
  wmemmove_s(
    &a_Object->m_Value.u_String.m_String[0],
    a_Object->m_Value.u_String.m_Capacity,
    &a_Object->m_Value.u_String.m_String[a_Size],
    a_Object->m_Value.u_String.m_Capacity - a_Size
  );
  a_Object->m_Value.u_String.m_Size -= a_Size;
  CObjectString_Shrink(a_Object, a_Object->m_Value.u_String.m_Size);
  wmemset(&a_Object->m_Value.u_String.m_String[a_Object->m_Value.u_String.m_Size], 0, sizeof(wchar_t) * a_Size);
  CObjectString_Shrink(a_Object, a_Object->m_Value.u_String.m_Size);
}

void
CObjectString_FindFirst(
  CObject  *a_Object,
  CObject  *a_Value,
  uint64_t  a_Start,
  bool     *a_Found,
  uint64_t *a_Index
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  assert(a_Found != NULL);
  assert(a_Index != NULL);
  if(a_Start >= a_Object->m_Value.u_String.m_Size)
  {
    *a_Found = false;
    return;
  }
  wchar_t *l_Char = wcsstr(&a_Object->m_Value.u_String.m_String[a_Start], a_Value->m_Value.u_String.m_String);
  if(l_Char == NULL)
  {
    *a_Found = false;
    return;
  }
  *a_Found = true;
  *a_Index = l_Char - a_Object->m_Value.u_String.m_String;
}

void
CObjectString_FindLast(
  CObject  *a_Object,
  CObject  *a_Value,
  uint64_t  a_Start,
  bool     *a_Found,
  uint64_t *a_Index
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  assert(a_Found != NULL);
  assert(a_Index != NULL);
  if(a_Start >= a_Object->m_Value.u_String.m_Size)
  {
    *a_Found = false;
    return;
  }
  wchar_t *l_Char = wcsstr(&a_Object->m_Value.u_String.m_String[a_Start], a_Value->m_Value.u_String.m_String);
  if(l_Char == NULL)
  {
    *a_Found = false;
    return;
  }
  *a_Found = true;
  *a_Index = l_Char - a_Object->m_Value.u_String.m_String;
}

void
CObjectString_Replace(
  CObject *a_Object,
  CObject *a_What,
  CObject *a_With
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  uint64_t l_WhatSize = a_What->m_Value.u_String.m_Size;
  bool     l_WhatPosFound;
  uint64_t l_WhatPos;
  CObjectString_FindFirst(a_Object, a_What, 0, &l_WhatPosFound, &l_WhatPos);
  if(!l_WhatPosFound)
  {
    return;
  }
  uint64_t l_WhatEnd     = l_WhatPos + l_WhatSize;
  uint64_t l_WhatLen     = a_Object->m_Value.u_String.m_Size - l_WhatEnd;
  uint64_t l_WhatNewSize = a_Object->m_Value.u_String.m_Size - l_WhatSize + a_With->m_Value.u_String.m_Size;
  CObjectString_Grow(a_Object, l_WhatNewSize);
  wmemmove_s(
    &a_Object->m_Value.u_String.m_String[l_WhatPos + a_With->m_Value.u_String.m_Size],
    a_Object->m_Value.u_String.m_Capacity - (l_WhatPos + a_With->m_Value.u_String.m_Size),
    &a_Object->m_Value.u_String.m_String[l_WhatEnd],
    l_WhatLen
  );
  wmemcpy_s(
    &a_Object->m_Value.u_String.m_String[l_WhatPos],
    a_Object->m_Value.u_String.m_Capacity - l_WhatPos,
    a_With->m_Value.u_String.m_String,
    a_With->m_Value.u_String.m_Size
  );
  CObjectString_Grow(a_Object, l_WhatNewSize);
}

void
CObjectString_Compare(
  CObject                 *a_Object1,
  CObject                 *a_Object2,
  CObjectStringComparison *a_Comparison
)
{
  assert(a_Object1 != NULL);
  assert(a_Object1->m_Type == k_ObjectString);
  assert(a_Object2 != NULL);
  assert(a_Object2->m_Type == k_ObjectString);
  assert(a_Comparison != NULL);
  if(a_Object1->m_Value.u_String.m_Size < a_Object2->m_Value.u_String.m_Size)
  {
    *a_Comparison = k_CObjectStringComparisonLessThan;
  }
  else if(a_Object1->m_Value.u_String.m_Size > a_Object2->m_Value.u_String.m_Size)
  {
    *a_Comparison = k_CObjectStringComparisonGreaterThan;
  }
  else
  {
    *a_Comparison = wcscmp(a_Object1->m_Value.u_String.m_String, a_Object2->m_Value.u_String.m_String) == 0
                    ? k_CObjectStringComparisonEqual
                    : k_CObjectStringComparisonLessThan;
  }
}

void
CObjectString_StartsWith(
  CObject *a_Object,
  CObject *a_Value,
  bool    *a_StartsWith
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  assert(a_StartsWith != NULL);
  if(a_Value->m_Value.u_String.m_Size > a_Object->m_Value.u_String.m_Size)
  {
    *a_StartsWith = false;
    return;
  }
  *a_StartsWith
    = wcsncmp(a_Object->m_Value.u_String.m_String, a_Value->m_Value.u_String.m_String, a_Value->m_Value.u_String.m_Size)
   == 0;
}

void
CObjectString_EndsWith(
  CObject *a_Object,
  CObject *a_Value,
  bool    *a_EndsWith
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  assert(a_EndsWith != NULL);
  if(a_Value->m_Value.u_String.m_Size > a_Object->m_Value.u_String.m_Size)
  {
    *a_EndsWith = false;
    return;
  }
  *a_EndsWith
    = wcsncmp(
        &a_Object->m_Value.u_String.m_String[a_Object->m_Value.u_String.m_Size - a_Value->m_Value.u_String.m_Size],
        a_Value->m_Value.u_String.m_String,
        a_Value->m_Value.u_String.m_Size
      )
   == 0;
}

void
CObjectString_Contains(
  CObject *a_Object,
  CObject *a_Value,
  bool    *a_Contains
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  assert(a_Contains != NULL);
  if(a_Value->m_Value.u_String.m_Size > a_Object->m_Value.u_String.m_Size)
  {
    *a_Contains = false;
    return;
  }
  *a_Contains = wcsstr(a_Object->m_Value.u_String.m_String, a_Value->m_Value.u_String.m_String) != NULL;
}

CObject *
CObjectString_Substring(
  CObject *a_Object,
  uint64_t a_Start,
  uint64_t a_End
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Start < a_End);
  assert(a_End <= a_Object->m_Value.u_String.m_Size);
  CObject *l_Object;
  CObjectString_New(a_End - a_Start, &a_Object->m_Value.u_String.m_String[a_Start], &l_Object);
  return l_Object;
}

void
CObjectList_New(
  // NOLINTBEGIN(bugprone-easily-swappable-parameters)
  CObjectType a_ItemType,
  uint64_t    a_ItemCount,
  // NOLINTEND(bugprone-easily-swappable-parameters)
  CObject   **a_Object,
  ...
);

void
CObjectList_PushBack(
  CObject *a_Object,
  uint64_t a_Count,
  ...
);

void
CObjectString_Split(
  CObject  *a_Object,
  CObject  *a_Value,
  CObject **a_List
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  assert(a_List != NULL);
  CObject *l_List;
  CObjectList_New(k_ObjectString, 0, &l_List, NULL);
  assert(l_List != NULL);
  uint64_t l_Start = 0;
  uint64_t l_End   = 0;
  bool     l_Found = true;
  while(l_Found)
  {
    CObjectString_FindFirst(a_Object, a_Value, l_Start, &l_Found, &l_End);
    if(l_Found)
    {
      if(l_End > l_Start)
      {
        CObject *l_Substring = CObjectString_Substring(a_Object, l_Start, l_End);
        assert(l_Substring != NULL);
        CObjectList_PushBack(l_List, 1, l_Substring);
      }
      l_Start = l_End + a_Value->m_Value.u_String.m_Size;
    }
  }
  if(l_Start < a_Object->m_Value.u_String.m_Size)
  {
    CObject *l_Substring = CObjectString_Substring(a_Object, l_Start, a_Object->m_Value.u_String.m_Size);
    assert(l_Substring != NULL);
    CObjectList_PushBack(l_List, 1, l_Substring);
  }
  *a_List = l_List;
}

void
CObjectString_Extend(
  CObject *a_Object,
  uint64_t a_Index,
  CObject *a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Index < a_Object->m_Value.u_String.m_Size);
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectString);
  uint64_t l_Size = a_Object->m_Value.u_String.m_Size + a_Value->m_Value.u_String.m_Size;
  CObjectString_Grow(a_Object, l_Size);
  wmemmove_s(
    &a_Object->m_Value.u_String.m_String[a_Index + a_Value->m_Value.u_String.m_Size],
    a_Object->m_Value.u_String.m_Capacity - (a_Index + a_Value->m_Value.u_String.m_Size),
    &a_Object->m_Value.u_String.m_String[a_Index],
    a_Object->m_Value.u_String.m_Capacity - a_Index
  );
  wmemcpy_s(
    &a_Object->m_Value.u_String.m_String[a_Index],
    a_Object->m_Value.u_String.m_Capacity - a_Index,
    a_Value->m_Value.u_String.m_String,
    a_Value->m_Value.u_String.m_Size
  );
}

void
CObjectString_Swap(
  CObject *a_Object,
  uint64_t a_Index1,
  uint64_t a_Index2
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  assert(a_Object->m_Value.u_String.m_String != NULL);
  assert(a_Index1 < a_Object->m_Value.u_String.m_Size);
  assert(a_Index2 < a_Object->m_Value.u_String.m_Size);
  wchar_t l_Tmp                                 = a_Object->m_Value.u_String.m_String[a_Index1];
  a_Object->m_Value.u_String.m_String[a_Index1] = a_Object->m_Value.u_String.m_String[a_Index2];
  a_Object->m_Value.u_String.m_String[a_Index2] = l_Tmp;
}

void
CObjectString_Free(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectString);
  free(a_Object->m_Value.u_String.m_String);
  free(a_Object);
}

void
CObjectPair_New(
  CObject  *a_Left,
  CObject  *a_Right,
  CObject **a_Object
)
{
  assert(a_Left != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type                = k_ObjectPair;
  l_Object->m_Value.u_Pair.m_Left = a_Left;
  CObject_GetType(a_Left, &l_Object->m_Value.u_Pair.m_LeftType);
  l_Object->m_Value.u_Pair.m_Right = a_Right;
  CObject_GetType(a_Right, &l_Object->m_Value.u_Pair.m_RightType);
  *a_Object = l_Object;
}

void
CObjectPair_NewFrom(
  CObject  *a_Value,
  CObject **a_Object
)
{
  assert(a_Value != NULL);
  assert(a_Value->m_Type == k_ObjectPair);
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type                     = k_ObjectPair;
  l_Object->m_Value.u_Pair.m_Left      = a_Value->m_Value.u_Pair.m_Left;
  l_Object->m_Value.u_Pair.m_LeftType  = a_Value->m_Value.u_Pair.m_LeftType;
  l_Object->m_Value.u_Pair.m_Right     = a_Value->m_Value.u_Pair.m_Right;
  l_Object->m_Value.u_Pair.m_RightType = a_Value->m_Value.u_Pair.m_RightType;
  *a_Object                            = l_Object;
}

void
CObjectPair_GetValue(
  CObject  *a_Object,
  // NOLINTBEGIN(bugprone-easily-swappable-parameters)
  CObject **a_Left,
  CObject **a_Right
  // NOLINTEND(bugprone-easily-swappable-parameters)
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectPair);
  if(a_Left != NULL)
  {
    *a_Left = a_Object->m_Value.u_Pair.m_Left;
  }
  if(a_Right != NULL)
  {
    *a_Right = a_Object->m_Value.u_Pair.m_Right;
  }
}

void
CObjectPair_SetValue(
  CObject *a_Object,
  CObject *a_Left,
  CObject *a_Right
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectPair);
  if(a_Left != NULL)
  {
    a_Object->m_Value.u_Pair.m_Left = a_Left;
    CObject_GetType(a_Left, &a_Object->m_Value.u_Pair.m_LeftType);
  }
  if(a_Right != NULL)
  {
    a_Object->m_Value.u_Pair.m_Right = a_Right;
    CObject_GetType(a_Right, &a_Object->m_Value.u_Pair.m_RightType);
  }
}

void
CObjectPair_Free(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectPair);
  CObject_Free(a_Object->m_Value.u_Pair.m_Left);
  CObject_Free(a_Object->m_Value.u_Pair.m_Right);
  free(a_Object);
}

void
CObjectList_New(
  // NOLINTBEGIN(bugprone-easily-swappable-parameters)
  CObjectType a_ItemType,
  uint64_t    a_ItemCount,
  // NOLINTEND(bugprone-easily-swappable-parameters)
  CObject   **a_Object,
  ...
)
{
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type                     = k_ObjectList;
  l_Object->m_Value.u_List.m_ItemType  = a_ItemType;
  l_Object->m_Value.u_List.m_ItemCount = a_ItemCount;
  l_Object->m_Value.u_List.m_Items     = (CObject **) malloc(sizeof(CObject *) * a_ItemCount);
  assert(l_Object->m_Value.u_List.m_Items != NULL);
  va_list l_Args;
  va_start(l_Args, a_ItemCount);
  for(uint64_t l_Index = 0; l_Index < a_ItemCount; l_Index++)
  {
    l_Object->m_Value.u_List.m_Items[l_Index] = va_arg(l_Args, CObject *);
    CObjectType l_Type;
    CObject_GetType(l_Object->m_Value.u_List.m_Items[l_Index], &l_Type);
    assert(l_Type == l_Object->m_Value.u_List.m_ItemType);
  }
  va_end(l_Args);
  *a_Object = l_Object;
}

void
CObjectList_NewFrom(
  CObject  *a_Value,
  CObject **a_Object
)
{
  assert(a_Value != NULL);
  assert(a_Object != NULL);
  switch(a_Value->m_Type)
  {
    case k_ObjectBoolean :
    case k_ObjectInteger :
    case k_ObjectFloating :
    {
      CObjectType l_Type;
      CObject_GetType(a_Value, &l_Type);
      CObject *l_Object;
      CObjectList_New(l_Type, 1, &l_Object, a_Value);
      *a_Object = l_Object;
      break;
    }
    case k_ObjectString :
    {
      CObject *l_Object;
      CObjectList_New(k_ObjectString, 0, &l_Object, NULL);
      for(uint64_t l_Index = 0; l_Index < a_Value->m_Value.u_String.m_Size; l_Index++)
      {
        CObject *l_Char = CObjectString_Substring(a_Value, l_Index, l_Index + 1);
        assert(l_Char != NULL);
        CObjectList_PushBack(l_Object, 1, l_Char);
      }
      *a_Object = l_Object;
      break;
    }
    case k_ObjectPair :
    {
      CObject *l_Object;
      CObjectList_New(k_ObjectPair, 2, &l_Object, a_Value->m_Value.u_Pair.m_Left, a_Value->m_Value.u_Pair.m_Right);
      *a_Object = l_Object;
      break;
    }
    case k_ObjectList :
    {
      CObject *l_Object;
      CObjectList_New(a_Value->m_Value.u_List.m_ItemType, a_Value->m_Value.u_List.m_ItemCount, &l_Object, NULL);
      for(uint64_t l_Index = 0; l_Index < a_Value->m_Value.u_List.m_ItemCount; l_Index++)
      {
        l_Object->m_Value.u_List.m_Items[l_Index] = a_Value->m_Value.u_List.m_Items[l_Index];
      }
      *a_Object = l_Object;
      break;
    }
    case k_ObjectDictionary :
    {
      CObject *l_Object;
      CObjectList_New(k_ObjectDictionary, 0, &l_Object, NULL);
      for(uint64_t l_Index = 0; l_Index < a_Value->m_Value.u_Dictionary.m_PairCount; l_Index++)
      {
        CObject *l_Pair;
        CObjectList_GetAt(a_Value->m_Value.u_Dictionary.m_Pairs, l_Index, &l_Pair);
        CObject *l_Key, *l_Value;
        CObjectPair_GetValue(l_Pair, &l_Key, &l_Value);
        CObjectList_PushBack(l_Object, 2, l_Key, l_Value);
      }
      *a_Object = l_Object;
      break;
    }
    default :
    {
      assert(false);
      break;
    }
  }
}

void
CObjectList_GetAt(
  CObject  *a_Object,
  uint64_t  a_Index,
  CObject **a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Index < a_Object->m_Value.u_List.m_ItemCount);
  assert(a_Value != NULL);
  *a_Value = a_Object->m_Value.u_List.m_Items[a_Index];
}

void
CObjectList_GetFirst(
  CObject  *a_Object,
  CObject **a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Value != NULL);
  CObject *l_First;
  CObjectList_GetAt(a_Object, 0, &l_First);
  *a_Value = l_First;
}

void
CObjectList_GetLast(
  CObject  *a_Object,
  CObject **a_Value
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Value != NULL);
  CObject *l_Last;
  CObjectList_GetAt(a_Object, a_Object->m_Value.u_List.m_ItemCount - 1, &l_Last);
  *a_Value = l_Last;
}

void
CObjectList_GetIndex(
  CObject *a_Object,
  CObject *a_Item,
  int64_t *a_Index
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Item != NULL);
  assert(a_Index != NULL);
  for(uint64_t l_Index = 0; l_Index < a_Object->m_Value.u_List.m_ItemCount; l_Index++)
  {
    if(a_Object->m_Value.u_List.m_Items[l_Index] == a_Item)
    {
      *a_Index = (int64_t) l_Index;
      return;
    }
  }
  *a_Index = -1;
}

void
CObjectList_GetSize(
  CObject  *a_Object,
  uint64_t *a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Size != NULL);
  *a_Size = a_Object->m_Value.u_List.m_ItemCount;
}

void
CObjectList_GetCapacity(
  CObject  *a_Object,
  uint64_t *a_Capacity
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Capacity != NULL);
  *a_Capacity = a_Object->m_Value.u_List.m_ItemCapacity;
}

void
CObjectList_GetStorage(
  CObject   *a_Object,
  CObject ***a_Storage
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Storage != NULL);
  *a_Storage = a_Object->m_Value.u_List.m_Items;
}

void
CObjectList_GetStorageEnd(
  CObject   *a_Object,
  CObject ***a_StorageEnd
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_StorageEnd != NULL);
  *a_StorageEnd = a_Object->m_Value.u_List.m_Items + a_Object->m_Value.u_List.m_ItemCount;
}

void
CObjectList_GetItemType(
  CObject     *a_Object,
  CObjectType *a_ItemType
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_ItemType != NULL);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
}

void
CObjectList_Shrink(
  CObject *a_Object,
  uint64_t a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  if(a_Size < a_Object->m_Value.u_List.m_ItemCapacity)
  {
    for(uint64_t l_Index = a_Object->m_Value.u_List.m_ItemCount; l_Index > a_Size; l_Index--)
    {
      CObject_Free(a_Object->m_Value.u_List.m_Items[l_Index]);
    }
    if(a_Size < a_Object->m_Value.u_List.m_ItemCount)
    {
      a_Object->m_Value.u_List.m_ItemCount = a_Size;
    }
    a_Object->m_Value.u_List.m_ItemCapacity = a_Size;
    a_Object->m_Value.u_List.m_Items        = (CObject **
    ) realloc(a_Object->m_Value.u_List.m_Items, sizeof(CObject *) * a_Object->m_Value.u_List.m_ItemCapacity);
    assert(a_Object->m_Value.u_List.m_Items != NULL);
  }
}

void
CObjectList_Grow(
  CObject *a_Object,
  uint64_t a_Size
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  if(a_Size > a_Object->m_Value.u_List.m_ItemCapacity)
  {
    a_Object->m_Value.u_List.m_ItemCapacity = a_Size;
    a_Object->m_Value.u_List.m_Items        = (CObject **
    ) realloc(a_Object->m_Value.u_List.m_Items, sizeof(CObject *) * a_Object->m_Value.u_List.m_ItemCapacity);
    assert(a_Object->m_Value.u_List.m_Items != NULL);
  }
}

void
CObjectList_Clear(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  for(uint64_t l_Index = 0; l_Index < a_Object->m_Value.u_List.m_ItemCount; l_Index++)
  {
    CObject_Free(a_Object->m_Value.u_List.m_Items[l_Index]);
  }
  a_Object->m_Value.u_List.m_ItemCount = 0;
}

void
CObjectList_Fit(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  if(a_Object->m_Value.u_List.m_ItemCount < a_Object->m_Value.u_List.m_ItemCapacity)
  {
    a_Object->m_Value.u_List.m_ItemCapacity = a_Object->m_Value.u_List.m_ItemCount;
    a_Object->m_Value.u_List.m_Items        = (CObject **
    ) realloc(a_Object->m_Value.u_List.m_Items, sizeof(CObject *) * a_Object->m_Value.u_List.m_ItemCapacity);
    assert(a_Object->m_Value.u_List.m_Items != NULL);
  }
}

void
CObjectList_InsertAt(
  CObject *a_Object,
  uint64_t a_Index,
  uint64_t a_Count,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Index <= a_Object->m_Value.u_List.m_ItemCount);
  assert(a_Count > 0);
  assert(a_Index + a_Count <= a_Object->m_Value.u_List.m_ItemCount);
  CObjectList_Grow(a_Object, a_Object->m_Value.u_List.m_ItemCount + a_Count);
  for(uint64_t l_Index = a_Object->m_Value.u_List.m_ItemCount; l_Index > a_Index; l_Index--)
  {
    a_Object->m_Value.u_List.m_Items[l_Index] = a_Object->m_Value.u_List.m_Items[l_Index - a_Count];
  }
  va_list l_Args;
  va_start(l_Args, a_Count);
  for(uint64_t l_Index = 0; l_Index < a_Count; l_Index++)
  {
    a_Object->m_Value.u_List.m_Items[a_Index + l_Index] = va_arg(l_Args, CObject *);
    CObjectType l_Type;
    CObject_GetType(a_Object->m_Value.u_List.m_Items[a_Index + l_Index], &l_Type);
    assert(l_Type == a_Object->m_Value.u_List.m_ItemType);
  }
  va_end(l_Args);
  a_Object->m_Value.u_List.m_ItemCount += a_Count;
}

void
CObjectList_RemoveAt(
  CObject *a_Object,
  uint64_t a_Index,
  uint64_t a_Count,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Index < a_Object->m_Value.u_List.m_ItemCount);
  assert(a_Count > 0);
  assert(a_Index + a_Count <= a_Object->m_Value.u_List.m_ItemCount);
  va_list l_Args;
  va_start(l_Args, a_Count);
  for(uint64_t l_Index = 0; l_Index < a_Count; l_Index++)
  {
    CObject **l_Item = va_arg(l_Args, CObject **);
    assert(l_Item != NULL);
    *l_Item = a_Object->m_Value.u_List.m_Items[a_Index + l_Index];
  }
  va_end(l_Args);
  for(uint64_t l_Index = a_Index; l_Index < a_Object->m_Value.u_List.m_ItemCount - a_Count; l_Index++)
  {
    a_Object->m_Value.u_List.m_Items[l_Index] = a_Object->m_Value.u_List.m_Items[l_Index + a_Count];
  }
  a_Object->m_Value.u_List.m_ItemCount -= a_Count;
  CObjectList_Shrink(a_Object, a_Object->m_Value.u_List.m_ItemCount);
}

void
CObjectList_PushBack(
  CObject *a_Object,
  uint64_t a_Count,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Count > 0);
  CObjectList_Grow(a_Object, a_Object->m_Value.u_List.m_ItemCount + a_Count);
  va_list l_Args;
  va_start(l_Args, a_Count);
  for(uint64_t l_Index = a_Object->m_Value.u_List.m_ItemCount; l_Index < a_Object->m_Value.u_List.m_ItemCount + a_Count;
      l_Index++)
  {
    a_Object->m_Value.u_List.m_Items[l_Index] = va_arg(l_Args, CObject *);
    CObjectType l_Type;
    CObject_GetType(a_Object->m_Value.u_List.m_Items[l_Index], &l_Type);
    assert(l_Type == a_Object->m_Value.u_List.m_ItemType);
  }
  va_end(l_Args);
  a_Object->m_Value.u_List.m_ItemCount += a_Count;
}

void
CObjectList_PushFront(
  CObject *a_Object,
  uint64_t a_Count,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Count > 0);
  CObjectList_Grow(a_Object, a_Object->m_Value.u_List.m_ItemCount + a_Count);
  va_list l_Args;
  va_start(l_Args, a_Count);
  for(uint64_t l_Index = a_Count; l_Index < a_Object->m_Value.u_List.m_ItemCount + a_Count; l_Index++)
  {
    a_Object->m_Value.u_List.m_Items[l_Index] = a_Object->m_Value.u_List.m_Items[l_Index - a_Count];
  }
  for(uint64_t l_Index = 0; l_Index < a_Count; l_Index++)
  {
    a_Object->m_Value.u_List.m_Items[l_Index] = va_arg(l_Args, CObject *);
    CObjectType l_Type;
    CObject_GetType(a_Object->m_Value.u_List.m_Items[l_Index], &l_Type);
    assert(l_Type == a_Object->m_Value.u_List.m_ItemType);
  }
  va_end(l_Args);
  a_Object->m_Value.u_List.m_ItemCount += a_Count;
}

void
CObjectList_PopBack(
  CObject *a_Object,
  uint64_t a_Count,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Count > 0);
  assert(a_Count <= a_Object->m_Value.u_List.m_ItemCount);
  va_list l_Args;
  va_start(l_Args, a_Count);
  for(uint64_t l_Index = a_Object->m_Value.u_List.m_ItemCount - a_Count; l_Index < a_Object->m_Value.u_List.m_ItemCount;
      l_Index++)
  {
    CObject **l_Item = va_arg(l_Args, CObject **);
    assert(l_Item != NULL);
    *l_Item = a_Object->m_Value.u_List.m_Items[l_Index];
  }
  va_end(l_Args);
  a_Object->m_Value.u_List.m_ItemCount -= a_Count;
}

void
CObjectList_PopFront(
  CObject *a_Object,
  uint64_t a_Count,
  ...
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Count > 0);
  assert(a_Count <= a_Object->m_Value.u_List.m_ItemCount);
  va_list l_Args;
  va_start(l_Args, a_Count);
  for(uint64_t l_Index = 0; l_Index < a_Count; l_Index++)
  {
    CObject **l_Item = va_arg(l_Args, CObject **);
    assert(l_Item != NULL);
    *l_Item = a_Object->m_Value.u_List.m_Items[l_Index];
  }
  va_end(l_Args);
  for(uint64_t l_Index = a_Count; l_Index < a_Object->m_Value.u_List.m_ItemCount; l_Index++)
  {
    a_Object->m_Value.u_List.m_Items[l_Index - a_Count] = a_Object->m_Value.u_List.m_Items[l_Index];
  }
  a_Object->m_Value.u_List.m_ItemCount -= a_Count;
}

void
CObjectList_Swap(
  CObject *a_Object,
  uint64_t a_Index1,
  uint64_t a_Index2
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  assert(a_Object->m_Value.u_List.m_Items != NULL);
  assert(a_Index1 < a_Object->m_Value.u_List.m_ItemCount);
  assert(a_Index2 < a_Object->m_Value.u_List.m_ItemCount);
  CObject *l_Tmp                             = a_Object->m_Value.u_List.m_Items[a_Index1];
  a_Object->m_Value.u_List.m_Items[a_Index1] = a_Object->m_Value.u_List.m_Items[a_Index2];
  a_Object->m_Value.u_List.m_Items[a_Index2] = l_Tmp;
}

void
CObjectList_Free(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectList);
  for(uint64_t l_Index = 0; l_Index < a_Object->m_Value.u_List.m_ItemCount; l_Index++)
  {
    CObject_Free(a_Object->m_Value.u_List.m_Items[l_Index]);
  }
  free((void *) a_Object->m_Value.u_List.m_Items);
  free(a_Object);
}

void
CObjectDictionary_New(
  // NOLINTBEGIN(bugprone-easily-swappable-parameters)
  CObjectType a_LeftType,
  CObjectType a_RightType,
  uint64_t    a_PairCount,
  CObject   **a_Object,
  // NOLINTEND(bugprone-easily-swappable-parameters)
  ...
)
{
  assert(a_Object != NULL);
  CObject *l_Object = malloc(sizeof(CObject));
  assert(l_Object != NULL);
  l_Object->m_Type                               = k_ObjectDictionary;
  l_Object->m_Value.u_Dictionary.m_PairLeftType  = a_LeftType;
  l_Object->m_Value.u_Dictionary.m_PairRightType = a_RightType;
  CObjectList_New(k_ObjectPair, 0, &l_Object->m_Value.u_Dictionary.m_Pairs, NULL);
  va_list l_Args;
  va_start(l_Args, a_PairCount);
  for(uint64_t l_Index = 0; l_Index < a_PairCount; l_Index++)
  {
    CObject *l_Arg = va_arg(l_Args, CObject *);
    assert(l_Arg != NULL);
    CObjectType l_Type;
    CObject_GetType(l_Arg, &l_Type);
    assert(l_Type == k_ObjectPair);
    CObject_GetType(l_Arg->m_Value.u_Pair.m_Left, &l_Type);
    assert(l_Type == l_Object->m_Value.u_Dictionary.m_PairLeftType);
    CObject_GetType(l_Arg->m_Value.u_Pair.m_Right, &l_Type);
    assert(l_Type == l_Object->m_Value.u_Dictionary.m_PairRightType);
    CObject *l_ArgId;
    uint64_t l_ArgId_;
    CObject_GetId(l_Arg->m_Value.u_Pair.m_Left, &l_ArgId_);
    CObject *l_Arg_;
    CObjectInteger_New(k_IntegerUnsigned, k_Integer64, &l_ArgId, l_ArgId_);
    CObjectPair_New(l_ArgId, l_Arg, &l_Arg_);
    CObjectList_PushBack(l_Object->m_Value.u_Dictionary.m_Pairs, 1, l_Arg_);
  }
  va_end(l_Args);
  l_Object->m_Value.u_Dictionary.m_PairCount    = l_Object->m_Value.u_Dictionary.m_Pairs->m_Value.u_List.m_ItemCount;
  l_Object->m_Value.u_Dictionary.m_PairCapacity = l_Object->m_Value.u_Dictionary.m_Pairs->m_Value.u_List.m_ItemCapacity;
  *a_Object                                     = l_Object;
}

void
CObjectDictionary_NewFrom(
  CObject  *a_Value,
  CObject **a_Object
)
{
  assert(a_Value != NULL);
  assert(a_Object != NULL);
  switch(a_Value->m_Type)
  {
    case k_ObjectPair :
    {
      CObjectType l_LeftType, l_RightType;
      CObject    *l_Object;
      CObject_GetType(a_Value->m_Value.u_Pair.m_Left, &l_LeftType);
      CObject_GetType(a_Value->m_Value.u_Pair.m_Right, &l_RightType);
      CObjectDictionary_New(l_LeftType, l_RightType, 1, &l_Object, a_Value);
      *a_Object = l_Object;
      break;
    }
    case k_ObjectList :
    {
      CObject *l_Object;
      CObjectDictionary_New(a_Value->m_Value.u_List.m_ItemType, a_Value->m_Value.u_List.m_ItemType, 0, &l_Object, NULL);
      for(uint64_t l_Index = 0; l_Index < a_Value->m_Value.u_List.m_ItemCount; l_Index += 2)
      {
        CObject *l_Arg;
        CObjectPair_New(a_Value->m_Value.u_List.m_Items[l_Index], a_Value->m_Value.u_List.m_Items[l_Index + 1], &l_Arg);
        CObjectList_PushBack(l_Object->m_Value.u_Dictionary.m_Pairs, 1, l_Arg);
      }
      *a_Object = l_Object;
      break;
    }
    case k_ObjectDictionary :
    {
      CObject *l_Object;
      CObjectDictionary_New(
        a_Value->m_Value.u_Dictionary.m_PairLeftType, a_Value->m_Value.u_Dictionary.m_PairRightType, 0, &l_Object, NULL
      );
      for(uint64_t l_Index = 0; l_Index < a_Value->m_Value.u_Dictionary.m_Pairs->m_Value.u_List.m_ItemCount; l_Index++)
      {
        CObject *l_Arg;
        CObjectList_GetAt(a_Value->m_Value.u_Dictionary.m_Pairs, l_Index, &l_Arg);
        CObjectList_PushBack(l_Object->m_Value.u_Dictionary.m_Pairs, 1, l_Arg);
      }
      *a_Object = l_Object;
      break;
    }
    default :
    {
      assert(false);
      break;
    }
  }
}

void
CObjectDictionary_Free(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  assert(a_Object->m_Type == k_ObjectDictionary);
  CObjectList_Free(a_Object->m_Value.u_Dictionary.m_Pairs);
  free(a_Object);
}

void
CObject_Free(
  CObject *a_Object
)
{
  assert(a_Object != NULL);
  CObjectType l_Type;
  CObject_GetType(a_Object, &l_Type);
  switch(l_Type)
  {
    case k_ObjectBoolean :
    {
      CObjectBoolean_Free(a_Object);
      break;
    }
    case k_ObjectInteger :
    {
      CObjectInteger_Free(a_Object);
      break;
    }
    case k_ObjectFloating :
    {
      CObjectFloating_Free(a_Object);
      break;
    }
    case k_ObjectString :
    {
      CObjectString_Free(a_Object);
      break;
    }
    case k_ObjectPair :
    {
      CObjectPair_Free(a_Object);
      break;
    }
    case k_ObjectList :
    {
      CObjectList_Free(a_Object);
      break;
    }
    case k_ObjectDictionary :
    {
      CObjectDictionary_Free(a_Object);
      break;
    }
    default :
    {
      assert(false);
      break;
    }
  }
}
