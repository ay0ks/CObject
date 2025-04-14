# CObject : Shallow typed object system in C
------
 * Single root type `CObject`.
 * Several object kinds: `Boolean`, `Integer`, `Floating`, `String`, `Pair`, `List`, `Dictionary`.
 * You create it, you destroy it: `CObject{Type}_New`, `CObject{Type}_Free`, `CObject_Free`.

### Reference:
 * Retrieve type: `CObject_GetType`.
 * Initialize internal key: `CObject_Initialize`.
 * Retrieve identificators:
   * Naive: `CObject_GetId` - Doesn't consider object's value, every object gets an unique id.
   * Reasonable: `CObject_GetIdReasonable` - Objects with the same type and value get the same id.
 * Free a generic object: `CObject_Free`
 * Convert one type to another: `CObject{Type}_NewFrom` (Partially complete.)
 * Integer signedness (`CObjectIntegerSignedness`) and sizes (`CObjectIntegerSize`):
   * `k_IntegerSigned` and `k_IntegerUnsigned`
   * `k_Integer8`, `k_Integer16`, `k_Integer32`, `k_Integer64`
 * Floating sizes (`CObjectFloatingSize`):
   * `k_Floating32`, `k_Floating64`
   * `k_Floating80` (It actually being 80 bits is platform and implementation dependent.)
 * Boolean operations:
   * `CObjectBoolean_GetValue`, `CObjectBoolean_SetValue`
 * Integer operations:
   * `CObjectInteger_GetSignedness`, `CObjectInteger_GetSize`
   * `CObjectInteger_GetValue`, `CObjectInteger_SetValue`
 * Floating operations:
   * `CObjectFloating_GetSize`
   * `CObjetcFloating_GetValue`, `CObjectFloating_SetValue`
 * String operations (Unfinished):
   * `CObjectString_GetAt`, `CObjectString_GetFirst`, `CObjectString_GetLast`
   * `CObjectString_GetSize`, `CObjectString_GetCapacity`
   * `CObjectString_IsEmpty`
   * `CObjectString_GetStorage`, `CObjectString_GetStorageEnd`
   * `CObjectString_Shrink`, `CObjectString_Grow`, `CObjectString_Fit`
   * `CObjectString_Clear`
   * `CObjectString_InsertAt`, `CObjectString_RemoveAt`
   * `CObjectString_PushBack`, `CObjectString_PushFront`
   * `CObjectString_PopBack`, `CObjectString_PopFront`
   * `CObjectString_FindFirst`, `CObjectString_FindLast`
   * `CObjectString_Replace`
   * `CObjectString_Compare`
   * `CObjectString_StartsWith`, `CObjectString_EndsWith`, `CObjectString_Contains`
   * `CObjectString_Substring`
   * `CObjectString_Split`
   * `CObjectString_Extend`
   * `CObjectString_Swap`
 * Pair operations:
   * `CObjectPair_GetValue`, `CObjectPair_SetValue`
 * List operations:
   * `CObjectList_GetAt`, `CObjectList_GetFirst`, `CObjectList_GetLast`, `CObjectList_GetIndex`
   * `CObjectList_GetSize`, `CObjectList_GetCapacity`, `CObjectList_GetItemType`
   * `CObjectList_GetStorage`, `CObjectList_GetStorageEnd`
   * `CObjectList_Shrink`, `CObjectList_Grow`, `CObjectList_Fit`
   * `CObjectList_Clear`
   * `CObjectList_InsertAt`, `CObjectList_RemoveAt`
   * `CObjectList_PushBack`, `CObjectList_PushFront`
   * `CObjectList_PopBack`, `CObjectList_PopFront`
   * `CObjectList_Swap`
 * Dictionary operations (Unfinished):   
   * ...

### Todo:
 * Handle `CObjectType.k_ObjectAny`.
 * Finish `CObjectString_*` and `CObjectDictionary_*`.
 * Add tests.

 * Publish the first release.
