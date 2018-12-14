#include "base.h"


#ifndef TI_ALLOCATOR_FREE_DEFRAG_MAX_LOOPS
  #define TI_ALLOCATOR_FREE_DEFRAG_MAX_LOOPS 10
#endif

struct FreeNode;

typedef struct FreeNode {
  size_t length;
  struct FreeNode* prev;
  struct FreeNode* next;
} FreeNode;


inline extern
void FreeNode_init (FreeNode* fn, size_t length, FreeNode* prev, FreeNode* next) {
  fn->length = length;
  fn->prev = prev;
  fn->next = next;
}

inline extern
FreeNode FreeNode_create (size_t length, FreeNode* prev, FreeNode* next) {
  FreeNode fn;

  FreeNode_init(&fn, length, prev, next);

  return fn;
}


typedef struct Allocator {
  size_t block_size;
  uint8_t* memory;
  uint8_t* end;
  uint8_t* top;
  FreeNode* free_list;
} Allocator;


inline extern
void Allocator_init (Allocator* a, size_t max_memory, size_t block_size) {
  m_panic_assert(block_size >= sizeof(FreeNode), "Cannot initialize Allocator: block_size must be greater than or equal to sizeof(FreeNode) (%zu)", sizeof(FreeNode));
  m_panic_assert(max_memory > block_size, "Cannot initialize Allocator: max_memory must be greater than block_size");

  a->block_size = block_size;
  a->memory = (uint8_t*) malloc(max_memory - (max_memory % block_size));
  a->end = a->memory + max_memory;
  a->top = a->memory;
  a->free_list = NULL;
}

inline extern
Allocator Allocator_create (size_t max_memory, size_t block_size) {
  Allocator a;

  Allocator_init(&a, max_memory, block_size);

  return a;
}

inline extern
void Allocator_dispose (Allocator* a) {
  a->block_size = 0;

  if (a->memory != NULL) {
    free(a->memory);
    a->memory = NULL;
  }

  a->end = NULL;
  a->top = NULL;
  a->free_list = NULL;
}


inline extern
size_t Allocator_calc_block_count (Allocator* a, size_t byte_size) {
  return (byte_size / a->block_size) + (byte_size % a->block_size > 0);
}

inline extern
size_t Allocator_calc_total_memory (Allocator* a) {
  return a->end - a->memory;
}

inline extern
size_t Allocator_calc_unused_memory (Allocator* a) {
  return a->end - a->top;
}

inline extern
size_t Allocator_calc_used_memory (Allocator* a) {
  return a->top - a->memory;
}

inline extern
size_t Allocator_calc_free_memory (Allocator* a) {
  size_t free_blocks = 0;
      
  FreeNode* fn = a->free_list;
  
  while (fn != NULL) {
    free_blocks += fn->length;
    fn = fn->next;
  }

  return free_blocks * a->block_size;
}

inline extern
size_t Allocator_calc_available_memory (Allocator* a) {
  return Allocator_calc_free_memory(a) + Allocator_calc_unused_memory(a);
}


inline extern
bool Allocator_contains_address (Allocator* a, void* address) {
  return address >= (void*) a->memory && address < (void*) a->end;
}

inline extern
bool Allocator_contains_address_range (Allocator* a, void* address, size_t byte_range) {
  return address >= (void*) a->memory && (uint8_t*) address + byte_range <= a->end;
}


#define m_validate_size(alloc) \
  m_panic_assert( \
    alloc->top <= alloc->end, \
    "Allocator heap overflow: Max memory allocation of %zu bytes exceeded", \
    Allocator_calc_total_memory(alloc) \
  )

#define m_validate_address(alloc, addr) \
  m_panic_assert( \
    Allocator_contains_address(alloc, addr) \
    && ((size_t) ((uint8_t*) addr - sizeof(size_t) - a->memory)) % a->block_size == 0, \
    "Address is out of allocation bounds or is not a valid block-aligned address" \
  )


inline extern
void Allocator_dump_free_list (Allocator* a) {
  printf("Allocator<%zu, %zu>@%p -> free_list: {\n", Allocator_calc_total_memory(a), a->block_size, a->memory);

  FreeNode* fn = a->free_list;

  size_t i = 0;

  while (fn != NULL) {
    printf(
      "  %zu : %p : %zu %s (%zu bytes)\n",
      i ++,
      fn,
      fn->length,
      fn->length > 1? "blocks" : "block",
      a->block_size * fn->length
    );

    fn = fn->next;
  }

  printf("}\n");
}


inline
void Allocator_unlink_free_node (Allocator* a, FreeNode* free_node, size_t block_count) {
  if (block_count < free_node->length) {
    size_t rem_count = free_node->length - block_count;

    FreeNode* rem_node = (FreeNode*) ((uint8_t*) free_node + block_count * a->block_size);
    FreeNode_init(rem_node, rem_count, free_node->prev, free_node->next);

    if (rem_node->prev != NULL) rem_node->prev->next = rem_node;
    else a->free_list = rem_node;

    if (rem_node->next != NULL) rem_node->next->prev = rem_node;
  } else {
    if (free_node->prev != NULL) free_node->prev->next = free_node->next;
    else a->free_list = free_node->next;

    if (free_node->next != NULL) free_node->next->prev = free_node->prev;
  }
}


inline
uint8_t* Allocator_find_free_node (Allocator* a, size_t block_count) {
  FreeNode* fn = a->free_list;
  FreeNode* bf = NULL;

  while (fn != NULL) {
    if (fn->length == block_count) { // return fn
      bf = fn;
      break;
    } else if (fn->length > block_count) { // look for best fit
      if (bf == NULL
      ||  bf->length > fn->length) bf = fn;
    }

    fn = fn->next;
  }

  if (bf != NULL) Allocator_unlink_free_node(a, bf, block_count);

  return (uint8_t*) bf;
}

inline
uint8_t* Allocator_find_free_node_at (Allocator* a, void* address, size_t block_count) {
  FreeNode* fn = a->free_list;
  FreeNode* bf = NULL;

  while (fn != NULL) {
    if ((void*) fn == address) { // same address, check for fit
      if (fn->length >= block_count) bf = fn;
      break;
    }

    fn = fn->next;
  }

  if (bf != NULL) Allocator_unlink_free_node(a, bf, block_count);

  return (uint8_t*) bf;
}


inline extern
void Allocator_defragment (Allocator* a, size_t max_loops) {
  if (a->free_list == NULL) return;

  size_t loops = 0;

  size_t merges;
  FreeNode* fn;

  do {
    fn = a->free_list;
    merges = 0;

    while (fn != NULL) {
      uint8_t* fn_end_ptr = (uint8_t*) fn + a->block_size * fn->length;

      if (fn->next == NULL && fn_end_ptr == a->top) { // pop top nodes
        if (fn->prev != NULL) fn->prev->next = NULL;
        else a->free_list = NULL;

        a->top = (uint8_t*) fn;

        ++ merges;
      } else if (fn->next == (FreeNode*) fn_end_ptr) { // merge nodes
        fn->length += fn->next->length;
        fn->next = fn->next->next;

        if (fn->next != NULL) fn->next->prev = fn;

        ++ merges;
      }

      fn = fn->next;
    }

    ++ loops;
  } while (merges > 0 && loops < max_loops);
}

inline
void Allocator_make_free_node (Allocator* a, void* address, size_t block_count) {
  FreeNode* fptr = (FreeNode*) address;

  if (a->free_list == NULL) {
    FreeNode_init(fptr, block_count, NULL, NULL);
    a->free_list = fptr;
  } else {
    FreeNode* ln = NULL;
    FreeNode* fn = a->free_list;
    
    while (fn != NULL) {
      if ((uint8_t*) fn > (uint8_t*) address) { // insert new node before existing node
        FreeNode_init(fptr, block_count, fn->prev, fn);

        if (fn->prev != NULL) fn->prev->next = fptr;
        else a->free_list = fptr;

        fn->prev = fptr;
        break;
      }

      ln = fn;
      fn = fn->next;
    }

    if (fn == NULL) { // insert new node to end of existing nodes
      ln->next = fptr;
      FreeNode_init(fptr, block_count, ln, NULL);
    }
  }

  Allocator_defragment(a, TI_ALLOCATOR_FREE_DEFRAG_MAX_LOOPS);
}


inline extern
void* Allocator_allocate(Allocator* a, size_t byte_size) {
  size_t block_count = Allocator_calc_block_count(a, byte_size + sizeof(size_t));
  size_t total_byte_size = block_count * a->block_size;

  uint8_t* ptr = Allocator_find_free_node(a, block_count);

  if (ptr == NULL) {
    ptr = a->top;
    a->top += total_byte_size;

    m_validate_size(a);
  }

  memset(ptr, 0, total_byte_size);
  
  size_t* uptr = (size_t*) ptr;
  *uptr = block_count;

  return uptr + 1;
}


inline extern
void Allocator_deallocate (Allocator* a, void* ptr) {
  m_validate_address(a, ptr);

  size_t* uptr = (size_t*) ptr - 1;
  return Allocator_make_free_node(a, uptr, *uptr);
}


inline extern
void* Allocator_reallocate (Allocator* a, void* ptr, size_t new_byte_size) {
  m_validate_address(a, ptr);

  size_t* old_block_count = (size_t*) ptr - 1;
  size_t new_block_count = Allocator_calc_block_count(a, new_byte_size + sizeof(size_t));

  if (new_block_count != *old_block_count) { // requires resize
    uint8_t* new_ptr_end = (uint8_t*) old_block_count + new_block_count * a->block_size;

    if (new_block_count < *old_block_count) { // partial free
      Allocator_make_free_node(a, new_ptr_end, *old_block_count - new_block_count);
    } else { // grow
      uint8_t* old_ptr_end = (uint8_t*) ptr + *old_block_count * a->block_size;

      if (old_ptr_end == a->top) { // grow top
        a->top = new_ptr_end;
        *old_block_count = new_block_count;

        m_validate_size(a);
      } else { // try to grow in place
        size_t added_block_count = new_block_count - *old_block_count;
        void* new_ptr = Allocator_find_free_node_at(a, old_ptr_end, added_block_count);

        if (new_ptr != NULL) { // grow in place
          *old_block_count = new_block_count;

          memset(new_ptr, 0, added_block_count * a->block_size);
        } else { // create new and move data
          new_ptr = Allocator_allocate(a, new_byte_size);
          
          memcpy(new_ptr, ptr, new_byte_size);

          Allocator_deallocate(a, ptr);

          ptr = new_ptr;
        }
      }
    }
  }

  return ptr;
}