#pragma once

#pragma once

#include "base.h"


namespace ti {
  struct Allocator;
  struct FreeNode;


  extern "C" void FreeNode_init (FreeNode* fn, size_t length, FreeNode* prev, FreeNode* next);
  // extern "C" FreeNode FreeNode_create (size_t length, FreeNode* prev, FreeNode* next); // NOTE: (works but gives a warning)

  extern "C" void Allocator_init (Allocator* a, size_t max_memory, size_t block_size);
  // extern "C" Allocator Allocator_create (size_t max_memory, size_t block_size); // NOTE: (works but gives a warning)
  extern "C" void Allocator_dispose (Allocator* a);
  extern "C" size_t Allocator_calc_block_count (Allocator* a, size_t byte_size);
  extern "C" size_t Allocator_calc_total_memory (Allocator* a);
  extern "C" size_t Allocator_calc_unused_memory (Allocator* a);
  extern "C" size_t Allocator_calc_used_memory (Allocator* a);
  extern "C" size_t Allocator_calc_free_memory (Allocator* a);
  extern "C" size_t Allocator_calc_available_memory (Allocator* a);
  extern "C" bool Allocator_contains_address (Allocator* a, void* address);
  extern "C" bool Allocator_contains_address_range (Allocator* a, void* address, size_t byte_range);
  extern "C" void Allocator_dump_free_list (Allocator* a);
  extern "C" void Allocator_defragment (Allocator* a, size_t max_loops);
  extern "C" void* Allocator_allocate(Allocator* a, size_t byte_size);
  extern "C" void Allocator_deallocate (Allocator* a, void* ptr);
  extern "C" void* Allocator_reallocate (Allocator* a, void* ptr, size_t new_byte_size);


  struct FreeNode {
    size_t length;
    FreeNode* prev;
    FreeNode* next;

    inline FreeNode () = default;
    inline FreeNode (size_t in_length, FreeNode* in_prev, FreeNode* in_next) {
      FreeNode_init(this, in_length, in_prev, in_next);
    }
  };


  struct Allocator {
    size_t block_size;
    uint8_t* memory;
    uint8_t* end;
    uint8_t* top;
    FreeNode* free_list;

    inline Allocator () = default;
    inline Allocator (size_t max_memory, size_t in_block_size) {
      Allocator_init(this, max_memory, in_block_size);
    }

    inline void dispose () {
      return Allocator_dispose(this);
    }

    inline ~Allocator () {
      dispose();
    }


    inline size_t calc_block_count (size_t byte_size) {
      return Allocator_calc_block_count(this, byte_size);
    }


    inline size_t calc_total_memory () {
      return Allocator_calc_total_memory(this);
    }

    inline size_t calc_unused_memory () {
      return Allocator_calc_unused_memory(this);
    }

    inline size_t calc_used_memory () {
      return Allocator_calc_used_memory(this);
    }

    inline size_t calc_free_memory () {
      return Allocator_calc_free_memory(this);
    }

    inline size_t calc_available_memory () {
      return Allocator_calc_available_memory(this);
    }
    

    inline bool contains_address (void* address) {
      return Allocator_contains_address(this, address);
    }

    inline bool contains_address_range (void* address, size_t byte_range) {
      return Allocator_contains_address_range(this, address, byte_range);
    }


    inline void dump_free_list () {
      return Allocator_dump_free_list(this);
    }


    inline void defragment (size_t max_loops = 1) {
      return Allocator_defragment(this, max_loops);
    }


    inline void* allocate (size_t byte_size) {
      return Allocator_allocate(this, byte_size);
    }

    inline void deallocate (void* ptr) {
      return Allocator_deallocate(this, ptr);
    }

    inline void* reallocate (void* ptr, size_t new_byte_size) {
      return Allocator_reallocate(this, ptr, new_byte_size);
    }
  };
}