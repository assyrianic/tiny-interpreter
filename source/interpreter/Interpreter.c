#include "base.h"
#include "Allocator.c"


#ifdef TI_SAFE_MODE
  #ifdef _WIN32
    #define m_safemode_error(fmt, ...) m_panic_error(fmt, __VA_ARGS__)
    #define m_safemode_assert(cond, fmt, ...) m_panic_assert(cond, fmt, __VA_ARGS__)
  #else
    #define m_safemode_error(fmt, ...) m_panic_error(fmt, ##__VA_ARGS__)
    #define m_safemode_assert(cond, fmt, ...) m_panic_assert(cond, fmt, ##__VA_ARGS__)
  #endif
#else
  #define m_safemode_error(fmt, ...)
  #define m_safemode_assert(cond, fmt, ...)
#endif


#ifdef TI_DEBUG_MODE
  #ifdef _WIN32
    #define m_debug_message(fmt, ...) { printf(fmt, __VA_ARGS__); putchar('\n'); }
  #else
    #define m_debug_message(fmt, ...) { printf(fmt, ##__VA_ARGS__); putchar('\n'); }
  #endif
#else
  #define m_debug_message(fmt, ...)
#endif


typedef enum {
  LT = -1,
  EQ = 0,
  GT = 1
} Comparison;


typedef enum {
  NO_OP,

  LIT8, LIT4, LIT2, LIT1,

  CLR8, CLR4, CLR2, CLR1,

  MOV8, MOV4, MOV2, MOV1,

  ADD8, ADD4, ADD2, ADD1,
  SUB8, SUB4, SUB2, SUB1,

  CMP8, CMP4, CMP2, CMP1,
  JMP, JEQ, JNE, JGE, JLE, JGT, JLT,

  PRINT8, PRINT4, PRINT2, PRINT1,

  LOAD8, LOAD4, LOAD2, LOAD1,
  STORE8, STORE4, STORE2, STORE1,
  PUSH8, PUSH4, PUSH2, PUSH1,
  POP8, POP4, POP2, POP1,

  CALL, RET, HALT,

  INSTRUCTION_COUNT
} Instruction;


#define DEFAULT_STACK_SIZE (1024 * 1024)


typedef struct {
  Allocator* allocator;

  uint8_t* instructions;
  uint8_t* max_instruction_address;

  uint8_t* stack;
  uint8_t* max_stack_address;

  uint8_t* op_registers;

  int8_t cmp;
  uint8_t* ip;
} Interpreter;


typedef struct {
  uint8_t* instructions;
  size_t instructions_length;
} Program;


#define RAX (0 * 8 + 0)
#define RCX (1 * 8 + 0)
#define RDX (2 * 8 + 0)
#define RBX (3 * 8 + 0)
#define RSI (4 * 8 + 0)
#define RDI (5 * 8 + 0)
#define RSP (6 * 8 + 0)
#define RBP (7 * 8 + 0)
#define R8 (8 * 8 + 0)
#define R9 (9 * 8 + 0)
#define R10 (10 * 8 + 0)
#define R11 (11 * 8 + 0)
#define R12 (12 * 8 + 0)
#define R13 (13 * 8 + 0)
#define R14 (14 * 8 + 0)
#define R15 (15 * 8 + 0)

#define EAX (0 * 8 + 4)
#define ECX (1 * 8 + 4)
#define EDX (2 * 8 + 4)
#define EBX (3 * 8 + 4)
#define ESI (4 * 8 + 4)
#define EDI (5 * 8 + 4)
#define ESP (6 * 8 + 4)
#define EBP (7 * 8 + 4)
#define R8D (8 * 8 + 4)
#define R9D (9 * 8 + 4)
#define R10D (10 * 8 + 4)
#define R11D (11 * 8 + 4)
#define R12D (12 * 8 + 4)
#define R13D (13 * 8 + 4)
#define R14D (14 * 8 + 4)
#define R15D (15 * 8 + 4)
 
#define AX (0 * 8 + 6)
#define CX (1 * 8 + 6)
#define DX (2 * 8 + 6)
#define BX (3 * 8 + 6)
#define SI (4 * 8 + 6)
#define DI (5 * 8 + 6)
#define SP (6 * 8 + 6)
#define BP (7 * 8 + 6)
#define R8W (8 * 8 + 6)
#define R9W (9 * 8 + 6)
#define R10W (10 * 8 + 6)
#define R11W (11 * 8 + 6)
#define R12W (12 * 8 + 6)
#define R13W (13 * 8 + 6)
#define R14W (14 * 8 + 6)
#define R15W (15 * 8 + 6)
 
#define AL (0 * 8 + 7)
#define CL (1 * 8 + 7)
#define DL (2 * 8 + 7)
#define BL (3 * 8 + 7)
#define SIL (4 * 8 + 7)
#define DIL (5 * 8 + 7)
#define SPL (6 * 8 + 7)
#define BPL (7 * 8 + 7)
#define R8B (8 * 8 + 7)
#define R9B (9 * 8 + 7)
#define R10B (10 * 8 + 7)
#define R11B (11 * 8 + 7)
#define R12B (12 * 8 + 7)
#define R13B (13 * 8 + 7)
#define R14B (14 * 8 + 7)
#define R15B (15 * 8 + 7)


const char * REGISTER_NAMES [128] = {
  [RAX] = "RAX", [RCX] = "RCX", [RDX] = "RDX", [RBX] = "RBX", [RSI] = "RSI", [RDI] = "RDI", [RSP] = "RSP", [RBP] = "RBP", [R8]  = "R8",  [R9]  = "R9",  [R10]  = "R10",  [R11]  = "R11",  [R12]  = "R12",  [R13]  = "R13",  [R14]  = "R14",  [R15]  = "R15",
  [EAX] = "EAX", [ECX] = "ECX", [EDX] = "EDX", [EBX] = "EBX", [ESI] = "ESI", [EDI] = "EDI", [ESP] = "ESP", [EBP] = "EBP", [R8D] = "R8D", [R9D] = "R9D", [R10D] = "R10D", [R11D] = "R11D", [R12D] = "R12D", [R13D] = "R13D", [R14D] = "R14D", [R15D] = "R15D",
  [AX]  = "AX",  [CX]  = "CX",  [DX]  = "DX",  [BX]  = "BX",  [SI]  = "SI",  [DI]  = "DI",  [SP]  = "SP",  [BP]  = "BP",  [R8W] = "R8W", [R9W] = "R9W", [R10W] = "R10W", [R11W] = "R11W", [R12W] = "R12W", [R13W] = "R13W", [R14W] = "R14W", [R15W] = "R15W",
  [AL]  = "AL",  [CL]  = "CL",  [DL]  = "DL",  [BL]  = "BL",  [SIL] = "SIL", [DIL] = "DIL", [SPL] = "SPL", [BPL] = "BPL", [R8B] = "R8B", [R9B] = "R9B", [R10B] = "R10B", [R11B] = "R11B", [R12B] = "R12B", [R13B] = "R13B", [R14B] = "R14B", [R15B] = "R15B"
};


uint8_t REGISTER_SIZES [128] = {
  [RAX] = 8, [RCX] = 8, [RDX] = 8, [RBX] = 8, [RSI] = 8, [RDI] = 8, [RSP] = 8, [RBP] = 8, [R8]  = 8, [R9]  = 8, [R10]  = 8, [R11]  = 8, [R12]  = 8, [R13]  = 8, [R14]  = 8, [R15]  = 8,
  [EAX] = 4, [ECX] = 4, [EDX] = 4, [EBX] = 4, [ESI] = 4, [EDI] = 4, [ESP] = 4, [EBP] = 4, [R8D] = 4, [R9D] = 4, [R10D] = 4, [R11D] = 4, [R12D] = 4, [R13D] = 4, [R14D] = 4, [R15D] = 4, 
  [AX]  = 2, [CX]  = 2, [DX]  = 2, [BX]  = 2, [SI]  = 2, [DI]  = 2, [SP]  = 2, [BP]  = 2, [R8W] = 2, [R9W] = 2, [R10W] = 2, [R11W] = 2, [R12W] = 2, [R13W] = 2, [R14W] = 2, [R15W] = 2, 
  [AL]  = 1, [CL]  = 1, [DL]  = 1, [BL]  = 1, [SIL] = 1, [DIL] = 1, [SPL] = 1, [BPL] = 1, [R8B] = 1, [R9B] = 1, [R10B] = 1, [R11B] = 1, [R12B] = 1, [R13B] = 1, [R14B] = 1, [R15B] = 1
};

uint8_t INSTRUCTION_DATA_SIZES [INSTRUCTION_COUNT] = {
  [NO_OP] = 0,

  [LIT8] = 1 + 8,
  [LIT4] = 1 + 4,
  [LIT2] = 1 + 2,
  [LIT1] = 1 + 1,

  [CLR8] = 1,
  [CLR4] = 1,
  [CLR2] = 1,
  [CLR1] = 1,

  [MOV8] = 1 + 1,
  [MOV4] = 1 + 1,
  [MOV2] = 1 + 1,
  [MOV1] = 1 + 1,

  [ADD8] = 1 + 1,
  [ADD4] = 1 + 1,
  [ADD2] = 1 + 1,
  [ADD1] = 1 + 1,

  [SUB8] = 1 + 1,
  [SUB4] = 1 + 1,
  [SUB2] = 1 + 1,
  [SUB1] = 1 + 1,

  [CMP8] = 1 + 1,
  [CMP4] = 1 + 1,
  [CMP2] = 1 + 1,
  [CMP1] = 1 + 1,

  [JMP] = 8,
  [JEQ] = 8,
  [JNE] = 8,
  [JGE] = 8,
  [JLE] = 8,
  [JGT] = 8,
  [JLT] = 8,

  [PRINT8] = 1,
  [PRINT4] = 1,
  [PRINT2] = 1,
  [PRINT1] = 1,

  [LOAD8] = 1 + 1 + 8,
  [LOAD4] = 1 + 1 + 8,
  [LOAD2] = 1 + 1 + 8,
  [LOAD1] = 1 + 1 + 8,

  [STORE8] = 1 + 8 + 1,
  [STORE4] = 1 + 8 + 1,
  [STORE2] = 1 + 8 + 1,
  [STORE1] = 1 + 8 + 1,

  [PUSH8] = 1,
  [PUSH4] = 1,
  [PUSH2] = 1,
  [PUSH1] = 1,

  [POP8] = 1,
  [POP4] = 1,
  [POP2] = 1,
  [POP1] = 1,

  [CALL] = 8,
  [RET] = 0,
  [HALT] = 0
};


#define m_validate_ip(i) \
  m_safemode_assert( \
    i->ip >= i->instructions && i->ip < i->max_instruction_address, \
    "Cannot execute: Instruction address %p is out of range (%p -> %p)", \
     i->ip,  i->instructions,  i->max_instruction_address \
  )


#define m_validate_reg(m, size) \
  m_safemode_assert( \
    *m < 128 && REGISTER_SIZES[*m] >= size, \
    "Cannot access register %s: A register of size %u or greater is required", \
    REGISTER_NAMES[*m], size \
  )


#define m_comparison_name(c) c == -1? "LT" : c == 0? "EQ" : c == 1? "GT" : "INVALID COMPARISON STATE"


inline extern
void Interpreter_init_stack (Interpreter* i, size_t stack_size) {
  i->stack = Allocator_allocate(i->allocator, stack_size);
  i->max_stack_address = i->stack + stack_size;
}


inline extern
void Interpreter_clear (Interpreter* i) {
  memset(i->op_registers, 0, 128);

  *(uint8_t**) (i->op_registers + RSP) = i->stack;
  *(uint8_t**) (i->op_registers + RBP) = i->stack;

  i->ip = i->instructions;
  i->cmp = 0;
}


inline extern
void Interpreter_init (Interpreter* i, Allocator* allocator, size_t stack_size) {
  i->allocator = allocator;

  i->op_registers = Allocator_allocate(i->allocator, 128);

  i->instructions = NULL;
  i->max_instruction_address = 0;

  Interpreter_init_stack(i, stack_size);

  Interpreter_clear(i);
}


inline extern
Interpreter Interpreter_create (Allocator* allocator, size_t stack_size) {
  Interpreter i;
  
  Interpreter_init(&i, allocator, stack_size);

  return i;
}


inline extern
void Interpreter_dispose (Interpreter* i) {
  if (i->op_registers != NULL) {
    Allocator_deallocate(i->allocator, i->op_registers);
    i->op_registers = NULL;
  }

  if (i->instructions != NULL) {
    Allocator_deallocate(i->allocator, i->instructions);
    i->instructions = NULL;
    i->ip = NULL;
    i->max_instruction_address = NULL;
  }

  if (i->stack != NULL) {
    Allocator_deallocate(i->allocator, i->stack);
    i->stack = NULL;
    i->max_stack_address = NULL;
  }

  i->allocator = NULL;
}


inline extern
void Interpreter_load (Interpreter* i, uint8_t* instructions, size_t instructions_length) {
  m_panic_assert(Allocator_contains_address(i->allocator, instructions), "Cannot load program: Program data must be allocated by the interpreter's internal allocator");

  i->instructions = instructions;
  i->max_instruction_address = instructions + instructions_length;
  i->ip = instructions;
}


inline extern
void Interpreter_load_program (Interpreter* i, Program p) {
  Interpreter_load(i, p.instructions, p.instructions_length);
}



inline
void* Interpreter_advance (Interpreter* i, int64_t offset) {
  void* ip = i->ip;

  m_validate_ip(i);

  i->ip += offset;

  return ip;
}



extern
void Interpreter_run (Interpreter* i) {
  #ifndef __INTELLISENSE__
    static void* dispatch_table [INSTRUCTION_COUNT] = {
      &&NO_OP,

      &&LIT8, &&LIT4, &&LIT2, &&LIT1,

      &&CLR8, &&CLR4, &&CLR2, &&CLR1,

      &&MOV8, &&MOV4, &&MOV2, &&MOV1,

      &&ADD8, &&ADD4, &&ADD2, &&ADD1,
      &&SUB8, &&SUB4, &&SUB2, &&SUB1,

      &&CMP8, &&CMP4, &&CMP2, &&CMP1,
      &&JMP, &&JEQ, &&JNE, &&JGE, &&JLE, &&JGT, &&JLT,

      &&PRINT8, &&PRINT4, &&PRINT2, &&PRINT1,

      &&LOAD8, &&LOAD4, &&LOAD2, &&LOAD1,
      &&STORE8, &&STORE4, &&STORE2, &&STORE1,
      &&PUSH8, &&PUSH4, &&PUSH2, &&PUSH1,
      &&POP8, &&POP4, &&POP2, &&POP1,

      &&CALL, &&RET, &&HALT,
    };

    #define DISPATCH goto *dispatch_table[*(uint8_t*) Interpreter_advance(i, 1)]
  #else
    #define DISPATCH
  #endif


  DISPATCH;
  

  NO_OP: {
    m_debug_message("NO_OP");
  } DISPATCH;


  LIT8: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 8);
    
    uint64_t* r = i->op_registers + *m;
    uint64_t* l = Interpreter_advance(i, 8);
    *r = *l;

    m_debug_message("LIT8 %s, 0x%016zux", REGISTER_NAMES[*m], *r);
  } DISPATCH;

  LIT4: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 4);
    
    uint32_t* r = i->op_registers + *m;
    uint32_t* l = Interpreter_advance(i, 4);
    *r = *l;

    m_debug_message("LIT4 %s, 0x%08x", REGISTER_NAMES[*m], *r);
  } DISPATCH;

  LIT2: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 2);
    
    uint16_t* r = i->op_registers + *m;
    uint16_t* l = Interpreter_advance(i, 2);
    *r = *l;

    m_debug_message("LIT2 %s, 0x%04x", REGISTER_NAMES[*m], *r);
  } DISPATCH;

  LIT1: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 1);
    
    uint8_t* r = i->op_registers + *m;
    uint8_t* l = Interpreter_advance(i, 1);
    *r = *l;

    m_debug_message("LIT1 %s, 0x%02x", REGISTER_NAMES[*m], *r);
  } DISPATCH;


  CLR8: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 8);

    uint64_t* r = i->op_registers + *m;

    *r = 0;

    m_debug_message("CLR8 %s", REGISTER_NAMES[*m]);
  } DISPATCH;

  CLR4: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 4);

    uint32_t* r = i->op_registers + *m;

    *r = 0;

    m_debug_message("CLR4 %s", REGISTER_NAMES[*m]);
  } DISPATCH;

  CLR2: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 2);

    uint16_t* r = i->op_registers + *m;

    *r = 0;

    m_debug_message("CLR2 %s", REGISTER_NAMES[*m]);
  } DISPATCH;

  CLR1: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 1);

    uint8_t* r = i->op_registers + *m;

    *r = 0;

    m_debug_message("CLR1 %s", REGISTER_NAMES[*m]);
  } DISPATCH;


  MOV8: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 8);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 8);

    uint64_t* ra = i->op_registers + *ma;
    uint64_t* rb = i->op_registers + *mb;

    *ra = *rb;

    m_debug_message("MOV8 %s, %s (0x%016zux)", REGISTER_NAMES[*ma], REGISTER_NAMES[*ma], *ra);
  } DISPATCH;

  MOV4: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 4);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 4);

    uint32_t* ra = i->op_registers + *ma;
    uint32_t* rb = i->op_registers + *mb;

    *ra = *rb;

    m_debug_message("MOV4 %s, %s (0x%08x)", REGISTER_NAMES[*ma], REGISTER_NAMES[*ma], *ra);
  } DISPATCH;

  MOV2: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 2);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 2);

    uint16_t* ra = i->op_registers + *ma;
    uint16_t* rb = i->op_registers + *mb;

    *ra = *rb;

    m_debug_message("MOV2 %s, %s (0x%04x)", REGISTER_NAMES[*ma], REGISTER_NAMES[*ma], *ra);
  } DISPATCH;

  MOV1: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 1);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 1);

    uint8_t* ra = i->op_registers + *ma;
    uint8_t* rb = i->op_registers + *mb;

    *ra = *rb;

    m_debug_message("MOV1 %s, %s (0x%04x)", REGISTER_NAMES[*ma], REGISTER_NAMES[*ma], *ra);
  } DISPATCH;


  ADD8: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 8);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 8);

    uint64_t* ra = i->op_registers + *ma;
    uint64_t* rb = i->op_registers + *mb;

    uint64_t o = *ra + *rb;

    m_debug_message("ADD8 %s (0x%016zux), %s (0x%016zux) (=0x%016zux)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*ma], *rb, o);

    *ra = o;
  } DISPATCH;

  ADD4: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 4);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 4);

    uint32_t* ra = i->op_registers + *ma;
    uint32_t* rb = i->op_registers + *mb;

    uint32_t o = *ra + *rb;

    m_debug_message("ADD4 %s (0x%08x), %s (0x%08x) (=0x%08x)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*ma], *rb, o);

    *ra = o;
  } DISPATCH;

  ADD2: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 2);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 2);

    uint16_t* ra = i->op_registers + *ma;
    uint16_t* rb = i->op_registers + *mb;

    uint16_t o = *ra + *rb;

    m_debug_message("ADD2 %s (0x%04x), %s (0x%04x) (=0x%04x)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*ma], *rb, o);

    *ra = o;
  } DISPATCH;

  ADD1: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 1);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 1);

    uint8_t* ra = i->op_registers + *ma;
    uint8_t* rb = i->op_registers + *mb;

    uint8_t o = *ra + *rb;

    m_debug_message("ADD1 %s (0x%02x), %s (0x%02x) (=0x%02x)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*ma], *rb, o);

    *ra = o;
  } DISPATCH;


  SUB8: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 8);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 8);

    uint64_t* ra = i->op_registers + *ma;
    uint64_t* rb = i->op_registers + *mb;

    uint64_t o = *ra - *rb;

    m_debug_message("SUB8 %s (0x%016zux), %s (0x%016zux) (=0x%016zux)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*ma], *rb, o);

    *ra = o;
  } DISPATCH;

  SUB4: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 4);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 4);

    uint32_t* ra = i->op_registers + *ma;
    uint32_t* rb = i->op_registers + *mb;

    uint32_t o = *ra - *rb;

    m_debug_message("SUB4 %s (0x%08x), %s (0x%08x) (=0x%08x)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*ma], *rb, o);

    *ra = o;
  } DISPATCH;

  SUB2: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 2);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 2);

    uint16_t* ra = i->op_registers + *ma;
    uint16_t* rb = i->op_registers + *mb;

    uint16_t o = *ra - *rb;

    m_debug_message("SUB2 %s (0x%04x), %s (0x%04x) (=0x%04x)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*ma], *rb, o);

    *ra = o;
  } DISPATCH;

  SUB1: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 1);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 1);

    uint8_t* ra = i->op_registers + *ma;
    uint8_t* rb = i->op_registers + *mb;

    uint8_t o = *ra - *rb;

    m_debug_message("SUB1 %s (0x%02x), %s (0x%02x) (=0x%02x)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*ma], *rb, o);

    *ra = o;
  } DISPATCH;


  CMP8: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 8);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 8);

    uint64_t* ra = i->op_registers + *ma;
    uint64_t* rb = i->op_registers + *mb;

    if (*ra < *rb) i->cmp = LT;
    else if (*ra > *rb) i->cmp = GT;
    else i->cmp = EQ;

    m_debug_message("CMP8 %s (0x%016zux), %s (0x%016zux) (=%s)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*mb], *rb, m_comparison_name(i->cmp));
  } DISPATCH;

  CMP4: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 4);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 4);

    uint32_t* ra = i->op_registers + *ma;
    uint32_t* rb = i->op_registers + *mb;

    if (*ra < *rb) i->cmp = LT;
    else if (*ra > *rb) i->cmp = GT;
    else i->cmp = EQ;

    m_debug_message("CMP4 %s (0x%08x), %s (0x%08x) (=%s)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*mb], *rb, m_comparison_name(i->cmp));
  } DISPATCH;

  CMP2: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 2);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 2);

    uint16_t* ra = i->op_registers + *ma;
    uint16_t* rb = i->op_registers + *mb;

    if (*ra < *rb) i->cmp = LT;
    else if (*ra > *rb) i->cmp = GT;
    else i->cmp = EQ;

    m_debug_message("CMP2 %s (0x%04x), %s (0x%04x) (=%s)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*mb], *rb, m_comparison_name(i->cmp));
  } DISPATCH;

  CMP1: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 1);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 1);

    uint8_t* ra = i->op_registers + *ma;
    uint8_t* rb = i->op_registers + *mb;

    if (*ra < *rb) i->cmp = LT;
    else if (*ra > *rb) i->cmp = GT;
    else i->cmp = EQ;

    m_debug_message("CMP1 %s (0x%02x), %s (0x%02x) (=%s)", REGISTER_NAMES[*ma], *ra, REGISTER_NAMES[*mb], *rb, m_comparison_name(i->cmp));
  } DISPATCH;


  JMP: {
    int64_t* j = Interpreter_advance(i, 8);

    void* o_ip = i->ip;

    Interpreter_advance(i, *j);

    m_debug_message("JMP %zd (%p -> %p)", *j, o_ip, i->ip);
  } DISPATCH;
  
  JEQ: {
    int64_t* j = Interpreter_advance(i, 8);

    if (i->cmp == EQ) {
      void* o_ip = i->ip;

      Interpreter_advance(i, *j);

      m_debug_message("JEQ %zd (%p -> %p)", *j, o_ip, i->ip);
    }
  } DISPATCH;
  
  JNE: {
    int64_t* j = Interpreter_advance(i, 8);

    if (i->cmp != EQ) {
      void* o_ip = i->ip;

      Interpreter_advance(i, *j);

      m_debug_message("JNE %zd (%p -> %p)", *j, o_ip, i->ip);
    }
  } DISPATCH;
  
  JGE: {
    int64_t* j = Interpreter_advance(i, 8);

    if (i->cmp >= EQ) {
      void* o_ip = i->ip;

      Interpreter_advance(i, *j);

      m_debug_message("JGE %zd (%p -> %p)", *j, o_ip, i->ip);
    }
  } DISPATCH;
  
  JLE: {
    int64_t* j = Interpreter_advance(i, 8);

    if (i->cmp <= EQ) {
      void* o_ip = i->ip;

      Interpreter_advance(i, *j);

      m_debug_message("JLE %zd (%p -> %p)", *j, o_ip, i->ip);
    }
  } DISPATCH;
  
  JGT: {
    int64_t* j = Interpreter_advance(i, 8);

    if (i->cmp == GT) {
      void* o_ip = i->ip;

      Interpreter_advance(i, *j);

      m_debug_message("JGT %zd (%p -> %p)", *j, o_ip, i->ip);
    }
  } DISPATCH;
  
  JLT: {
    int64_t* j = Interpreter_advance(i, 8);

    if (i->cmp == LT) {
      void* o_ip = i->ip;

      Interpreter_advance(i, *j);

      m_debug_message("JLT %zd (%p -> %p)", *j, o_ip, i->ip);
    }
  } DISPATCH;


  PRINT8: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 8);
    
    uint64_t* r = i->op_registers + *m;

    printf("%s value: 0x%016zux\n", REGISTER_NAMES[*m], *r);
  } DISPATCH;

  PRINT4: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 4);
    
    uint32_t* r = i->op_registers + *m;

    printf("%s value: 0x%08x\n", REGISTER_NAMES[*m], *r);
  } DISPATCH;

  PRINT2: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 2);
    
    uint16_t* r = i->op_registers + *m;

    printf("%s value: 0x%04x\n", REGISTER_NAMES[*m], *r);
  } DISPATCH;

  PRINT1: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 1);
    
    uint8_t* r = i->op_registers + *m;

    printf("%s value: 0x%02x\n", REGISTER_NAMES[*m], *r);
  } DISPATCH;


  LOAD8: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 8);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 8);

    uint64_t* ra = i->op_registers + *ma;
    uint8_t** rb = i->op_registers + *mb;
    int64_t*  of = Interpreter_advance(i, 8);

    uint64_t* mem = *rb + *of;

    m_safemode_assert(
      Allocator_contains_address_range(i->allocator, mem, 8),
      "Cannot load from memory (%p -> %p) not controlled by interpreter's designated allocator (%p -> %p)",
      mem, mem + 1,
      i->allocator->memory, i->allocator->end
    );

    *ra = *mem;

    m_debug_message("LOAD8 %s, %s + %zd (=0x%016zux)", REGISTER_NAMES[*ma], REGISTER_NAMES[*mb], *of, *ra);
  } DISPATCH;

  LOAD4: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 4);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 4);

    uint32_t* ra = i->op_registers + *ma;
    uint8_t** rb = i->op_registers + *mb;
    int64_t*  of = Interpreter_advance(i, 8);

    uint32_t* mem = *rb + *of;

    m_safemode_assert(
      Allocator_contains_address_range(i->allocator, mem, 4),
      "Cannot load from memory (%p -> %p) not controlled by interpreter's designated allocator (%p -> %p)",
      mem, mem + 1,
      i->allocator->memory, i->allocator->end
    );

    *ra = *mem;

    m_debug_message("LOAD4 %s, %s + %zd (=0x%08x)", REGISTER_NAMES[*ma], REGISTER_NAMES[*mb], *of, *ra);
  } DISPATCH;

  LOAD2: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 2);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 2);

    uint16_t* ra = i->op_registers + *ma;
    uint8_t** rb = i->op_registers + *mb;
    int64_t*  of = Interpreter_advance(i, 8);

    uint16_t* mem = *rb + *of;

    m_safemode_assert(
      Allocator_contains_address_range(i->allocator, mem, 2),
      "Cannot load from memory (%p -> %p) not controlled by interpreter's designated allocator (%p -> %p)",
      mem, mem + 1,
      i->allocator->memory, i->allocator->end
    );

    *ra = *mem;

    m_debug_message("LOAD2 %s, %s + %zd (=0x%04x)", REGISTER_NAMES[*ma], REGISTER_NAMES[*mb], *of, *ra);
  } DISPATCH;

  LOAD1: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 1);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 1);

    uint8_t*  ra = i->op_registers + *ma;
    uint8_t** rb = i->op_registers + *mb;
    int64_t*  of = Interpreter_advance(i, 8);

    uint8_t* mem = *rb + *of;

    m_safemode_assert(
      Allocator_contains_address_range(i->allocator, mem, 1),
      "Cannot load from memory (%p -> %p) not controlled by interpreter's designated allocator (%p -> %p)",
      mem, mem + 1,
      i->allocator->memory, i->allocator->end
    );

    *ra = *mem;

    m_debug_message("LOAD1 %s, %s + %zd (=0x%04x)", REGISTER_NAMES[*ma], REGISTER_NAMES[*mb], *of, *ra);
  } DISPATCH;


  STORE8: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 8);

    int64_t* of = Interpreter_advance(i, 8);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 8);

    uint8_t** ra = i->op_registers + *ma;
    uint64_t* rb = i->op_registers + *mb;

    uint64_t* mem = *ra + *of;

    m_safemode_assert(
      Allocator_contains_address_range(i->allocator, mem, 8),
      "Cannot store to memory (%p -> %p) not controlled by interpreter's designated allocator (%p -> %p)",
      mem, mem + 1,
      i->allocator->memory, i->allocator->end
    );

    *mem = *rb;

    m_debug_message("STORE8 %s + %zd, %s (=0x%016zux)", REGISTER_NAMES[*ma], *of, REGISTER_NAMES[*mb], *mem);
  } DISPATCH;

  STORE4: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 4);

    int64_t* of = Interpreter_advance(i, 8);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 4);

    uint8_t** ra = i->op_registers + *ma;
    uint32_t* rb = i->op_registers + *mb;

    uint32_t* mem = *ra + *of;

    m_safemode_assert(
      Allocator_contains_address_range(i->allocator, mem, 4),
      "Cannot store to memory (%p -> %p) not controlled by interpreter's designated allocator (%p -> %p)",
      mem, mem + 1,
      i->allocator->memory, i->allocator->end
    );

    *mem = *rb;

    m_debug_message("STORE4 %s + %zd, %s (=0x%08x)", REGISTER_NAMES[*ma], *of, REGISTER_NAMES[*mb], *mem);
  } DISPATCH;

  STORE2: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 2);

    int64_t* of = Interpreter_advance(i, 8);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 2);

    uint8_t** ra = i->op_registers + *ma;
    uint16_t* rb = i->op_registers + *mb;

    uint16_t* mem = *ra + *of;

    m_safemode_assert(
      Allocator_contains_address_range(i->allocator, mem, 2),
      "Cannot store to memory (%p -> %p) not controlled by interpreter's designated allocator (%p -> %p)",
      mem, mem + 1,
      i->allocator->memory, i->allocator->end
    );

    *mem = *rb;

    m_debug_message("STORE2 %s + %zd, %s (=0x%04x)", REGISTER_NAMES[*ma], *of, REGISTER_NAMES[*mb], *mem);
  } DISPATCH;

  STORE1: {
    uint8_t* ma = Interpreter_advance(i, 1);
    m_validate_reg(ma, 1);

    int64_t* of = Interpreter_advance(i, 8);

    uint8_t* mb = Interpreter_advance(i, 1);
    m_validate_reg(mb, 1);

    uint8_t** ra = i->op_registers + *ma;
    uint8_t* rb = i->op_registers + *mb;

    uint8_t* mem = *ra + *of;

    m_safemode_assert(
      Allocator_contains_address_range(i->allocator, mem, 1),
      "Cannot store to memory (%p -> %p) not controlled by interpreter's designated allocator (%p -> %p)",
      mem, mem + 1,
      i->allocator->memory, i->allocator->end
    );

    *mem = *rb;

    m_debug_message("STORE1 %s + %zd, %s (=0x%04x)", REGISTER_NAMES[*ma], *of, REGISTER_NAMES[*mb], *mem);
  } DISPATCH;


  POP8: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 8);
    
    uint64_t* r = i->op_registers + *m;

    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp >= i->stack + 8 && *rsp <= i->max_stack_address, "Stack underflow / Invalid RSP value: Cannot pop 8 byte value from stack of size %zu", (size_t) *rsp - (size_t) i->stack);
    
    *rsp = *rsp - 8;
    *r = *(uint64_t*) *rsp;

    m_debug_message("POP8 %s (=0x%016zux) (RSP 0x%016zux)", REGISTER_NAMES[*m], *r, (size_t) *rsp);
  } DISPATCH;

  POP4: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 4);
    
    uint32_t* r = i->op_registers + *m;

    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp >= i->stack + 4 && *rsp <= i->max_stack_address, "Stack underflow / Invalid RSP value: Cannot pop 4 byte value from stack of size %zu", (size_t) *rsp - (size_t) i->stack);
    
    *rsp = *rsp - 4;
    *r = *(uint32_t*) *rsp;

    m_debug_message("POP4 %s (=0x%08x) (RSP 0x%016zux)", REGISTER_NAMES[*m], *r, (size_t) *rsp);
  } DISPATCH;

  POP2: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 2);
    
    uint16_t* r = i->op_registers + *m;

    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp >= i->stack + 2 && *rsp <= i->max_stack_address, "Stack underflow / Invalid RSP value: Cannot pop 2 byte value from stack of size %zu", (size_t) *rsp - (size_t) i->stack);
    
    *rsp = *rsp - 2;
    *r = *(uint16_t*) *rsp;

    m_debug_message("POP2 %s (=0x%04x) (RSP 0x%016zux)", REGISTER_NAMES[*m], *r, (size_t) *rsp);
  } DISPATCH;

  POP1: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 1);
    
    uint8_t* r = i->op_registers + *m;

    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp >= i->stack + 1 && *rsp <= i->max_stack_address, "Stack underflow / Invalid RSP value: Cannot pop 1 byte value from stack of size 0");
    
    *rsp = *rsp - 1;
    *r = **rsp;

    m_debug_message("POP1 %s (=0x%02x) (RSP 0x%016zux)", REGISTER_NAMES[*m], *r, (size_t) *rsp);
  } DISPATCH;


  PUSH8: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 8);
    
    uint64_t* r = i->op_registers + *m;

    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp < i->max_stack_address - 8 && *rsp >= i->stack, "Stack overflow / Invalid RSP value: Cannot push 8 byte value to stack of size %zu / %zu", (size_t) *rsp - (size_t) i->stack, (size_t) i->max_stack_address);
    
    uint64_t* s = *rsp;
    *rsp = *rsp + 8;

    *s = *r;

    m_debug_message("PUSH8 %s (=0x%016zux) (RSP 0x%016zux)", REGISTER_NAMES[*m], *s, (size_t) *rsp);
  } DISPATCH;

  PUSH4: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 4);
    
    uint32_t* r = i->op_registers + *m;

    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp < i->max_stack_address - 4 && *rsp >= i->stack, "Stack overflow / Invalid RSP value: Cannot push 4 byte value to stack of size %zu / %zu", (size_t) *rsp - (size_t) i->stack, (size_t) i->max_stack_address);
    
    uint32_t* s = *rsp;
    *rsp = *rsp + 4;

    *s = *r;

    m_debug_message("PUSH4 %s (=0x%08x) (RSP 0x%016zux)", REGISTER_NAMES[*m], *s, (size_t) *rsp);
  } DISPATCH;

  PUSH2: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 2);
    
    uint16_t* r = i->op_registers + *m;

    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp < i->max_stack_address - 2 && *rsp >= i->stack, "Stack overflow / Invalid RSP value: Cannot push 2 byte value to stack of size %zu / %zu", (size_t) *rsp - (size_t) i->stack, (size_t) i->max_stack_address);
    
    uint16_t* s = *rsp;
    *rsp = *rsp + 2;

    *s = *r;

    m_debug_message("PUSH2 %s (=0x%04x) (RSP 0x%016zux)", REGISTER_NAMES[*m], *s, (size_t) *rsp);
  } DISPATCH;

  PUSH1: {
    uint8_t* m = Interpreter_advance(i, 1);
    m_validate_reg(m, 1);
    
    uint8_t* r = i->op_registers + *m;

    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp < i->max_stack_address - 1 && *rsp >= i->stack, "Stack overflow / Invalid RSP value: Cannot push 1 byte value to stack of max size %zu", (size_t) i->max_stack_address);
    
    uint8_t* s = *rsp;
    *rsp = *rsp + 1;

    *s = *r;

    m_debug_message("PUSH1 %s (=0x%02x) (RSP 0x%016zux)", REGISTER_NAMES[*m], *s, (size_t) *rsp);
  } DISPATCH;


  CALL: {
    uint64_t* a = Interpreter_advance(i, 8);
    
    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp <= i->max_stack_address - 8 && *rsp >= i->stack, "Stack overflow / Invalid RSP value: Cannot push 8 byte return address to stack of size %zu / %zu", (size_t) *rsp - (size_t) i->stack, (size_t) i->max_stack_address);

    uint8_t** s = *rsp;
    *rsp = *rsp + 8;
    *s = i->ip;

    i->ip = i->instructions + *a;

    m_validate_ip(i);

    m_debug_message("CALL %p (from %p)", i->ip, *s);
  } DISPATCH;

  RET: {
    uint8_t** rsp = i->op_registers + RSP;
    m_safemode_assert(*rsp >= i->stack + 8 && *rsp <= i->max_stack_address, "Stack underflow / Invalid RSP value: Cannot pop 8 byte return address from stack of size %zu", (size_t) *rsp - (size_t) i->stack);

    *rsp = *rsp - 8;
    uint8_t** a = *rsp;

    uint8_t* o_ip = i->ip;

    i->ip = *a;

    m_validate_ip(i);

    m_debug_message("RET %p (from %p)", i->ip, o_ip);
  } DISPATCH;

  HALT: return;
}