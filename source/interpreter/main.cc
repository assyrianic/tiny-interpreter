#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include "time.hh"

#define m_panic_header() printf("Internal error at [%s:%d]: ", __FILE__, __LINE__)
#define m_panic_error(fmt, ...) { m_panic_header(); printf(fmt, __VA_ARGS__); putchar('\n'); abort(); }
#define m_panic_assert(cond, fmt, ...) if (!(cond)) m_panic_error(fmt, __VA_ARGS__)

// #define INSTRUCTION_DEBUG

namespace Register {
  enum: uint8_t {
    S0, S1, S2, S3,
    S4, S5, S6, S7,
    S8, S9, SA, SB,
    SC, SD, SE, SF
  };

  static constexpr
  uint32_t 
    B0 = 0<<4,
    B1 = 4<<4,
    B2 = 6<<4,
    B3 = 7<<4;

  static constexpr
  uint8_t
    RAX = S0 | B0, RCX = S1 | B0, RDX = S2 | B0, RBX = S3 | B0,
    EAX = S0 | B1, ECX = S1 | B1, EDX = S2 | B1, EBX = S3 | B1,
     AX = S0 | B2,  CX = S1 | B2,  DX = S2 | B2,  BX = S3 | B2,
     AL = S0 | B3,  CL = S1 | B3,  DL = S2 | B3,  BL = S3 | B3,

    RSI = S4 | B0, RDI = S5 | B0, RSP = S6 | B0, RBP = S7 | B0,
    ESI = S4 | B1, EDI = S5 | B1, ESP = S6 | B1, EBP = S7 | B1,
     SI = S4 | B2,  DI = S5 | B2,  SP = S6 | B2,  BP = S7 | B2,
    SIL = S4 | B3, DIL = S5 | B3, SPL = S6 | B3, BPL = S7 | B3,

    R8  = S8 | B0, R9  = S9 | B0, R10  = SA | B0, R11  = SB | B0,
    R8D = S8 | B1, R9D = S9 | B1, R10D = SA | B1, R11D = SB | B1,
    R8W = S8 | B2, R9W = S9 | B2, R10W = SA | B2, R11W = SB | B2,
    R8B = S8 | B3, R9B = S9 | B3, R10B = SA | B3, R11B = SB | B3,

    R12  = SC | B0, R13  = SD | B0, R14  = SE | B0, R15  = SF | B0,
    R12D = SC | B1, R13D = SD | B1, R14D = SE | B1, R15D = SF | B1,
    R12W = SC | B2, R13W = SD | B2, R14W = SE | B2, R15W = SF | B2,
    R12B = SC | B3, R13B = SD | B3, R14B = SE | B3, R15B = SF | B3;

  static constexpr
  uint8_t MASK [64] = {
    RAX, RCX, RDX, RBX, RSI,  RDI,  RSP,  RBP,  R8,  R9,  R10,  R11,  R12,  R13,  R14,  R15,
    EAX, ECX, EDX, EBX, ESI,  EDI,  ESP,  EBP,  R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
     AX,  CX,  DX,  BX,  SI,   DI,   SP,   BP,  R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
     AL,  CL,  DL,  BL,  SIL,  DIL,  SPL,  BPL, R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B
  };

  static constexpr
  const char* NAME [64] = {
    "RAX", "RCX", "RDX", "RBX", "RSI",  "RDI",  "RSP",  "RBP",  "R8",  "R9",  "R10",  "R11",  "R12",  "R13",  "R14",  "R15",
    "EAX", "ECX", "EDX", "EBX", "ESI",  "EDI",  "ESP",  "EBP",  "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D",
     "AX",  "CX",  "DX",  "BX",  "SI",   "DI",   "SP",   "BP",  "R8W", "R9W", "R10W", "R11W", "R12W", "R13W", "R14W", "R15W",
     "AL",  "CL",  "DL",  "BL",  "SIL",  "DIL",  "SPL",  "BPL", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B", "R14B", "R15B"
  };

  inline constexpr
  uint8_t get_index (uint8_t mask) {
    return mask & 0x0F;
  }

  inline constexpr
  uint8_t get_offset (uint8_t mask) {
    return mask >> 4;
  }

  inline constexpr
  size_t get_size (uint8_t mask) {
    return 8 - get_offset(mask);
  }

  inline constexpr
  const char * get_name (uint8_t mask) {
    for (size_t i = 0; i < 64; i ++) {
      if (MASK[i] == mask) return NAME[i];
    }

    return NULL;
  }

  inline constexpr
  size_t get_array_offset (uint8_t mask) {
    size_t index  = get_index(mask);
    size_t offset = get_offset(mask);

    return index * 8llu + offset;
  }
};


struct RegisterSet {
  uint8_t memory [128] = { };

  inline constexpr
  void* operator [] (uint8_t mask) {
    return get_register(mask);
  }

  inline constexpr
  void* get_register (uint8_t mask) {
    return memory + Register::get_array_offset(mask); 
  }

  inline constexpr
  void* get_register (uint8_t mask, uint8_t min_size) {
    uint8_t index  = Register::get_index(mask);
    uint8_t offset = Register::get_offset(mask);

    #ifdef INSTRUCTION_SAFE
      uint8_t size = 8 - offset;
      m_panic_assert(size >= min_size, "Invalid Register size for Register %s, expected %u or greater, not %u", Register::get_name(mask), min_size, size);
    #endif

    return memory + (index * 8) + offset;
  }

  inline
  void clear (uint8_t* stack_ptr = NULL) {
    memset(memory, 0, 128);

    if (stack_ptr != NULL) {
      memcpy(get_register(Register::RSP), &stack_ptr, sizeof(uint8_t*));
      memcpy(get_register(Register::RBP), &stack_ptr, sizeof(uint8_t*));
    }
  }
};


namespace Comparison {
  static constexpr
  int8_t
    LT = -1,
    EQ = 0,
    GT = 1;

  inline constexpr
  const char* get_name (int8_t flag) {
    switch (flag) {
      case LT: return "LT";
      case EQ: return "EQ";
      case GT: return "GT";
      default: return "INVALID";
    }
  }
}


namespace Instruction {
  enum: uint8_t {
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
  };
}

template <typename A, typename B>
struct Pair {
  A a;
  B b;
};

struct Interpreter {
  static constexpr // 1mb stack memory
  size_t MAX_STACK_MEMORY = 1024 * 1024;

  uint8_t* instructions = NULL;
  size_t instruction_length = 0;

  uint8_t* stack = NULL;
  uint8_t* stack_base;
  
  RegisterSet op_registers;
  size_t IP = 0;
  int8_t CMP = 0;


  Interpreter () {
    init_stack();
  }

  ~Interpreter () { free(stack); }

  void init_stack () {
    m_panic_assert(stack == NULL, "Stack already initialized");
    stack = (uint8_t*) calloc(1, MAX_STACK_MEMORY);
    *(uint8_t**) op_registers[Register::RSP] = stack;
    *(uint8_t**) op_registers[Register::RBP] = stack;
    stack_base = stack;
  }

  void clear () {
    IP = 0;
    CMP = 0;
    op_registers.clear(stack);
  }

  void dispose (bool free_instructions = true) {
    if (free_instructions
    && instructions != NULL) {
      free(instructions);
      instructions = NULL;
    }

    if (stack != NULL) {
      free(stack);
      stack = NULL;
    }
  }
  

  inline
  void load (uint8_t* mem, size_t len) {
    instructions = mem;
    instruction_length = len;
  }

  inline
  void load (Pair<uint8_t*, size_t> pair) { return load(pair.a, pair.b); }


  inline
  size_t advance (int64_t amt = 1) {
    size_t c = IP;

    #ifdef INSTRUCTION_SAFE
      m_panic_assert(IP + amt > 0, "Cannot reverse %lld bytes, the instruction pointer is only at %llu", amt, IP);
      m_panic_assert(instruction_length >= IP + amt, "Cannot advance %lld bytes, there are only %llu bytes remaining in executable", amt, instruction_length - amt);
    #endif

    IP += amt;

    return c;
  }


  inline
  bool execute () {
    using namespace Instruction;
    
    uint8_t& op_code = instructions[advance()];

    switch (op_code) {
      case NO_OP: break;


      case LIT8: {
        auto& m = instructions[advance()];
        auto r = (uint64_t*) op_registers.get_register(m, 8);
        auto l = (uint64_t*) (instructions + advance(8));
        *r = *l;

        #ifdef INSTRUCTION_DEBUG
          printf("LIT8 %s, 0x%016llx\n", Register::get_name(m), *r);
        #endif
      } break;
      
      case LIT4: {
        auto& m = instructions[advance()];
        auto r = (uint32_t*) op_registers.get_register(m, 4);
        auto l = (uint32_t*) (instructions + advance(4));
        *r = *l;
        
        #ifdef INSTRUCTION_DEBUG
          printf("LIT4 %s, 0x%08x\n", Register::get_name(m), *r);
        #endif
      } break;
      
      case LIT2: {
        auto& m = instructions[advance()];
        auto r = (uint16_t*) op_registers.get_register(m, 2);
        auto l = (uint16_t*) (instructions + advance(2));
        *r = *l;
        
        #ifdef INSTRUCTION_DEBUG
          printf("LIT2 %s, 0x%04x\n", Register::get_name(m), *r);
        #endif
      } break;
      
      case LIT1: {
        auto& m = instructions[advance()];
        auto r = (uint8_t*) op_registers.get_register(m);
        auto l = (uint8_t*) (instructions + advance());
        *r = *l;
        
        #ifdef INSTRUCTION_DEBUG
          printf("LIT1 %s, 0x%02x\n", Register::get_name(m), *r);
        #endif
      } break;


      case CLR8: {
        auto& m = instructions[advance()];
        *(uint64_t*) op_registers.get_register(m, 8) = 0;
        
        #ifdef INSTRUCTION_DEBUG
          printf("CLR8 %s\n", Register::get_name(m));
        #endif
      } break;
      
      case CLR4: {
        auto& m = instructions[advance()];
        *(uint32_t*) op_registers.get_register(m, 4) = 0;
        
        #ifdef INSTRUCTION_DEBUG
          printf("CLR4 %s\n", Register::get_name(m));
        #endif
      } break;
      
      case CLR2: {
        auto& m = instructions[advance()];
        *(uint16_t*) op_registers.get_register(m, 2) = 0;
        
        #ifdef INSTRUCTION_DEBUG
          printf("CLR2 %s\n", Register::get_name(m));
        #endif
      } break;
      
      case CLR1: {
        auto& m = instructions[advance()];
        *(uint8_t*) op_registers.get_register(m) = 0;
        
        #ifdef INSTRUCTION_DEBUG
          printf("CLR1 %s\n", Register::get_name(m));
        #endif
      } break;


      case MOV8: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint64_t*) op_registers.get_register(ma, 8);
        auto b = (uint64_t*) op_registers.get_register(mb, 8);
        *a = *b;

        #ifdef INSTRUCTION_DEBUG
          printf("MOV8 %s, %s (0x%016llx)\n", Register::get_name(ma), Register::get_name(mb), *a);
        #endif
      } break;

      case MOV4: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint32_t*) op_registers.get_register(ma, 4);
        auto b = (uint32_t*) op_registers.get_register(mb, 4);
        *a = *b;
        
        #ifdef INSTRUCTION_DEBUG
          printf("MOV4 %s, %s (0x%08x)\n", Register::get_name(ma), Register::get_name(mb), *a);
        #endif
      } break;

      case MOV2: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint16_t*) op_registers.get_register(ma, 2);
        auto b = (uint16_t*) op_registers.get_register(mb, 2);
        *a = *b;
        
        #ifdef INSTRUCTION_DEBUG
          printf("MOV2 %s, %s (0x%04x)\n", Register::get_name(ma), Register::get_name(mb), *a);
        #endif
      } break;

      case MOV1: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint8_t*) op_registers.get_register(ma);
        auto b = (uint8_t*) op_registers.get_register(mb);
        *a = *b;
        
        #ifdef INSTRUCTION_DEBUG
          printf("MOV1 %s, %s (0x%02x)\n", Register::get_name(ma), Register::get_name(mb), *a);
        #endif
      } break;


      case ADD8: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint64_t*) op_registers.get_register(ma, 8);
        auto b = (uint64_t*) op_registers.get_register(mb, 8);
        auto r = *a + *b;

        #ifdef INSTRUCTION_DEBUG
          printf("ADD8 %s (0x%016llx), %s (0x%016llx) (=0x%016llx)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, r);
        #endif

        *a = r;
      } break;

      case ADD4: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint32_t*) op_registers.get_register(ma, 4);
        auto b = (uint32_t*) op_registers.get_register(mb, 4);
        auto r = *a + *b;

        #ifdef INSTRUCTION_DEBUG
          printf("ADD4 %s (0x%08x), %s (0x%08x) (=0x%08x)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, r);
        #endif

        *a = r;
      } break;

      case ADD2: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint16_t*) op_registers.get_register(ma, 2);
        auto b = (uint16_t*) op_registers.get_register(mb, 2);
        auto r = *a + *b;

        #ifdef INSTRUCTION_DEBUG
          printf("ADD2 %s (0x%04x), %s (0x%04x) (=0x%04x)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, r);
        #endif

        *a = r;
      } break;
      
      case ADD1: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint8_t*) op_registers.get_register(ma);
        auto b = (uint8_t*) op_registers.get_register(mb);
        auto r = *a + *b;

        #ifdef INSTRUCTION_DEBUG
          printf("ADD1 %s (0x%02x), %s (0x%02x) (=0x%02x)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, r);
        #endif

        *a = r;
      } break;


      case SUB8: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint64_t*) op_registers.get_register(ma, 8);
        auto b = (uint64_t*) op_registers.get_register(mb, 8);
        auto r = *a - *b;

        #ifdef INSTRUCTION_DEBUG
          printf("SUB8 %s (0x%016llx), %s (0x%016llx) (=0x%016llx)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, r);
        #endif

        *a = r;
      } break;

      case SUB4: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint32_t*) op_registers.get_register(ma, 4);
        auto b = (uint32_t*) op_registers.get_register(mb, 4);
        auto r = *a - *b;

        #ifdef INSTRUCTION_DEBUG
          printf("SUB4 %s (0x%08x), %s (0x%08x) (=0x%08x)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, r);
        #endif

        *a = r;
      } break;

      case SUB2: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint16_t*) op_registers.get_register(ma, 2);
        auto b = (uint16_t*) op_registers.get_register(mb, 2);
        auto r = *a - *b;

        #ifdef INSTRUCTION_DEBUG
          printf("SUB2 %s (0x%04x), %s (0x%04x) (=0x%04x)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, r);
        #endif

        *a = r;
      } break;
      
      case SUB1: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint8_t*) op_registers.get_register(ma);
        auto b = (uint8_t*) op_registers.get_register(mb);
        auto r = *a - *b;

        #ifdef INSTRUCTION_DEBUG
          printf("SUB1 %s (0x%02x), %s (0x%02x) (=0x%02x)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, r);
        #endif

        *a = r;
      } break;


      case CMP8: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint64_t*) op_registers.get_register(ma, 8);
        auto b = (uint64_t*) op_registers.get_register(mb, 8);

        if (*a < *b) CMP = Comparison::LT;
        else if (*a > *b) CMP = Comparison::GT;
        else CMP = Comparison::EQ;
        
        #ifdef INSTRUCTION_DEBUG
          printf("CMP8 %s (0x%016llx), %s (0x%016llx) (=%s)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, Comparison::get_name(CMP));
        #endif
      } break;

      case CMP4: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint32_t*) op_registers.get_register(ma, 4);
        auto b = (uint32_t*) op_registers.get_register(mb, 4);

        if (*a < *b) CMP = Comparison::LT;
        else if (*a > *b) CMP = Comparison::GT;
        else CMP = Comparison::EQ;
        
        #ifdef INSTRUCTION_DEBUG
          printf("CMP4 %s (0x%08x), %s (0x%08x) (=%s)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, Comparison::get_name(CMP));
        #endif
      } break;

      case CMP2: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint16_t*) op_registers.get_register(ma, 2);
        auto b = (uint16_t*) op_registers.get_register(mb, 2);

        if (*a < *b) CMP = Comparison::LT;
        else if (*a > *b) CMP = Comparison::GT;
        else CMP = Comparison::EQ;
        
        #ifdef INSTRUCTION_DEBUG
          printf("CMP2 %s (0x%04x), %s (0x%04x) (=%s)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, Comparison::get_name(CMP));
        #endif
      } break;

      case CMP1: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto a = (uint8_t*) op_registers.get_register(ma);
        auto b = (uint8_t*) op_registers.get_register(mb);

        if (*a < *b) CMP = Comparison::LT;
        else if (*a > *b) CMP = Comparison::GT;
        else CMP = Comparison::EQ;
        
        #ifdef INSTRUCTION_DEBUG
          printf("CMP1 %s (0x%02x), %s (0x%02x) (=%s)\n", Register::get_name(ma), *a, Register::get_name(mb), *b, Comparison::get_name(CMP));
        #endif
      } break;


      case JMP: {
        auto j = *(int64_t*) (instructions + advance(sizeof(int64_t)));
        advance(j);

        #ifdef INSTRUCTION_DEBUG
          printf("JMP %lld (=%llu)\n", j, IP);
        #endif
      } break;


      case JEQ: {
        auto j = *(int64_t*) (instructions + advance(sizeof(int64_t)));
        if (CMP == Comparison::EQ) {
          advance(j);
          #ifdef INSTRUCTION_DEBUG
            printf("JEQ %lld (=%llu)\n", j, IP);
          #endif
        }
      } break;

      case JNE: {
        auto j = *(int64_t*) (instructions + advance(sizeof(int64_t)));
        if (CMP != Comparison::EQ) {
          advance(j);
          #ifdef INSTRUCTION_DEBUG
            printf("JNE %lld (=%llu)\n", j, IP);
          #endif
        }
      } break;

      case JGE: {
        auto j = *(int64_t*) (instructions + advance(sizeof(int64_t)));
        if (CMP >= Comparison::EQ) {
          advance(j);
          #ifdef INSTRUCTION_DEBUG
            printf("JGE %lld (=%llu)\n", j, IP);
          #endif
        }
      } break;

      case JLE: {
        auto j = *(int64_t*) (instructions + advance(sizeof(int64_t)));
        if (CMP <= Comparison::EQ) {
          advance(j);
          #ifdef INSTRUCTION_DEBUG
            printf("JLE %lld (=%llu)\n", j, IP);
          #endif
        }
      } break;

      case JGT: {
        auto j = *(int64_t*) (instructions + advance(sizeof(int64_t)));
        if (CMP == Comparison::GT) {
          advance(j);
          #ifdef INSTRUCTION_DEBUG
            printf("JGT %lld (=%llu)\n", j, IP);
          #endif
        }
      } break;
      
      case JLT: {
        auto j = *(int64_t*) (instructions + advance(sizeof(int64_t)));
        if (CMP == Comparison::LT) {
          advance(j);
          #ifdef INSTRUCTION_DEBUG
            printf("JLT %lld (=%llu)\n", j, IP);
          #endif
        }
      } break;


      case PRINT8: {
        auto& m = instructions[advance()];
        auto r = (uint64_t*) op_registers.get_register(m, 8);
        printf("%s value: 0x%016llx\n", Register::get_name(m), *r);
      } break;

      case PRINT4: {
        auto& m = instructions[advance()];
        auto r = (uint32_t*) op_registers.get_register(m, 4);
        printf("%s value: 0x%08x\n", Register::get_name(m), *r);
      } break;
      
      case PRINT2: {
        auto& m = instructions[advance()];
        auto r = (uint16_t*) op_registers.get_register(m, 2);
        printf("%s value: 0x%04x\n", Register::get_name(m), *r);
      } break;

      case PRINT1: {
        auto& m = instructions[advance()];
        auto r = (uint8_t*) op_registers.get_register(m);
        printf("%s value: 0x%02x\n", Register::get_name(m), *r);
      } break;


      case LOAD8: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto o = (int64_t*) (instructions + advance(8));
        auto a = (uint64_t*) op_registers.get_register(ma, 8);
        auto b = (uint8_t**) op_registers.get_register(mb, 8);
        auto& r = *(uint64_t*) (*b + *o);
        *a = r;

        #ifdef INSTRUCTION_DEBUG
          printf("LOAD8 %s, %s + %lld (0x%016llx)\n", Register::get_name(ma), Register::get_name(mb), *o, r);
        #endif
      } break;

      case LOAD4: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto o = (int64_t*) (instructions + advance(8));
        auto a = (uint32_t*) op_registers.get_register(ma, 4);
        auto b = (uint8_t**) op_registers.get_register(mb, 8);
        auto& r = *(uint32_t*) (*b + *o);
        *a = r;

        #ifdef INSTRUCTION_DEBUG
          printf("LOAD4 %s, %s + %lld (0x%08x)\n", Register::get_name(ma), Register::get_name(mb), *o, r);
        #endif
      } break;

      case LOAD2: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto o = (int64_t*) (instructions + advance(8));
        auto a = (uint16_t*) op_registers.get_register(ma, 2);
        auto b = (uint8_t**) op_registers.get_register(mb, 8);
        auto& r = *(uint16_t*) (*b + *o);
        *a = r;

        #ifdef INSTRUCTION_DEBUG
          printf("LOAD2 %s, %s + %lld (0x%04x)\n", Register::get_name(ma), Register::get_name(mb), *o, r);
        #endif
      } break;

      case LOAD1: {
        auto& ma = instructions[advance()];
        auto& mb = instructions[advance()];
        auto o = (int64_t*) (instructions + advance(8));
        auto a = (uint8_t*) op_registers.get_register(ma);
        auto b = (uint8_t**) op_registers.get_register(mb, 8);
        auto& r = *(*b + *o);
        *a = r;

        #ifdef INSTRUCTION_DEBUG
          printf("LOAD1 %s, %s + %lld (0x%02x)\n", Register::get_name(ma), Register::get_name(mb), *o, r);
        #endif
      } break;


      case STORE8: {
        auto& ma = instructions[advance()];
        auto o = (int64_t*) (instructions + advance(8));
        auto& mb = instructions[advance()];
        auto a = (uint8_t**) op_registers.get_register(ma, 8);
        auto b = (uint64_t*) op_registers.get_register(mb, 8);
        auto& r = *(uint64_t*) (*a + *o);
        r = *b;

        #ifdef INSTRUCTION_DEBUG
          printf("STORE8 %s + %lld, %s (0x%016llx)\n", Register::get_name(ma), *o, Register::get_name(mb), r);
        #endif
      } break;

      case STORE4: {
        auto& ma = instructions[advance()];
        auto o = (int64_t*) (instructions + advance(8));
        auto& mb = instructions[advance()];
        auto a = (uint8_t**) op_registers.get_register(ma, 8);
        auto b = (uint32_t*) op_registers.get_register(mb, 4);
        auto& r = *(uint32_t*) (*a + *o);
        r = *b;

        #ifdef INSTRUCTION_DEBUG
          printf("STORE4 %s + %lld, %s (0x%08x)\n", Register::get_name(ma), *o, Register::get_name(mb), r);
        #endif
      } break;

      case STORE2: {
        auto& ma = instructions[advance()];
        auto o = (int64_t*) (instructions + advance(8));
        auto& mb = instructions[advance()];
        auto a = (uint8_t**) op_registers.get_register(ma, 8);
        auto b = (uint16_t*) op_registers.get_register(mb, 2);
        auto& r = *(uint16_t*) (*a + *o);
        r = *b;

        #ifdef INSTRUCTION_DEBUG
          printf("STORE2 %s + %lld, %s (0x%04x)\n", Register::get_name(ma), *o, Register::get_name(mb), r);
        #endif
      } break;

      case STORE1: {
        auto& ma = instructions[advance()];
        auto o = (int64_t*) (instructions + advance(8));
        auto& mb = instructions[advance()];
        auto a = (uint8_t**) op_registers.get_register(ma, 8);
        auto b = (uint8_t*) op_registers.get_register(mb);
        auto& r = *(*a + *o);
        r = *b;

        #ifdef INSTRUCTION_DEBUG
          printf("STORE1 %s + %lld, %s (0x%02x)\n", Register::get_name(ma), *o, Register::get_name(mb), r);
        #endif
      } break;


      case POP8: {
        auto& m = instructions[advance()];
        auto r  = (uint64_t*) op_registers.get_register(m, 8);
        auto rsp = (uint8_t**) op_registers[Register::RSP];

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base >= 8, "Stack Underflow: Cannot pop 8 byte value from stack, RSP is only %llu", *rsp);
        #endif

        *rsp = *rsp - 8;
        *r = *(uint64_t*) *rsp;

        #ifdef INSTRUCTION_DEBUG
          printf("POP8 %s (=0x%016llx) (RSP 0x%016llx)\n", Register::get_name(m), *r, (uint64_t) *rsp);
        #endif
      } break;

      case POP4: {
        auto& m = instructions[advance()];
        auto r  = (uint32_t*) op_registers.get_register(m, 4);
        auto rsp = (uint8_t**) op_registers[Register::RSP];

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base >= 4, "Stack Underflow: Cannot pop 4 byte value from stack, RSP is only %llu", *rsp);
        #endif

        *rsp = *rsp - 4;
        *r = *(uint32_t*) *rsp;

        #ifdef INSTRUCTION_DEBUG
          printf("POP4 %s (=0x%08x) (RSP 0x%016llx)\n", Register::get_name(m), *r, (uint64_t) *rsp);
        #endif
      } break;

      case POP2: {
        auto& m = instructions[advance()];
        auto r  = (uint16_t*) op_registers.get_register(m, 2);
        auto rsp = (uint8_t**) op_registers[Register::RSP];

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base >= 2, "Stack Underflow: Cannot pop 2 byte value from stack, RSP is only %llu", *rsp);
        #endif

        *rsp = *rsp - 2;
        *r = *(uint16_t*) *rsp;

        #ifdef INSTRUCTION_DEBUG
          printf("POP2 %s (=0x%04x) (RSP 0x%016llx)\n", Register::get_name(m), *r, (uint64_t) *rsp);
        #endif
      } break;

      case POP1: {
        auto& m = instructions[advance()];
        auto r  = (uint8_t*) op_registers.get_register(m);
        auto rsp = (uint8_t**) op_registers[Register::RSP];
        
        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base >= 1, "Stack Underflow: Cannot pop 1 byte value from stack, RSP is only %llu", *rsp);
        #endif

        *rsp = *rsp - 1;
        *r = **rsp;

        #ifdef INSTRUCTION_DEBUG
          printf("POP1 %s (=0x%02x) (RSP 0x%016llx)\n", Register::get_name(m), *r, (uint64_t) *rsp);
        #endif
      } break;


      case PUSH8: {
        auto& m = instructions[advance()];
        auto r  = (uint64_t*) op_registers.get_register(m, 8);
        auto rsp = (uint8_t**) op_registers[Register::RSP];

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base < MAX_STACK_MEMORY - 8, "Stack Overflow: Cannot push 8 byte value to stack, RSP is %llu (max is %llu)", *rsp, MAX_STACK_MEMORY);
        #endif

        auto& s = *(uint64_t*) *rsp;
        s = *r;
        *rsp = *rsp + 8;

        #ifdef INSTRUCTION_DEBUG
          printf("PUSH8 %s (=0x%016llx) (RSP 0x%016llx)\n", Register::get_name(m), s, (uint64_t) *rsp);
        #endif
      } break;

      case PUSH4: {
        auto& m = instructions[advance()];
        auto r  = (uint32_t*) op_registers.get_register(m, 4);
        auto rsp = (uint8_t**) op_registers[Register::RSP];

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base < MAX_STACK_MEMORY - 4, "Stack Overflow: Cannot push 4 byte value to stack, RSP is %llu (max is %llu)", *rsp, MAX_STACK_MEMORY);
        #endif

        auto& s = *(uint32_t*) *rsp;
        s = *r;
        *rsp = *rsp + 4;

        #ifdef INSTRUCTION_DEBUG
          printf("PUSH4 %s (=0x%08x) (RSP 0x%016llx)\n", Register::get_name(m), s, (uint64_t) *rsp);
        #endif
      } break;

      case PUSH2: {
        auto& m = instructions[advance()];
        auto r  = (uint16_t*) op_registers.get_register(m, 2);
        auto rsp = (uint8_t**) op_registers[Register::RSP];

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base < MAX_STACK_MEMORY - 2, "Stack Overflow: Cannot push 2 byte value to stack, RSP is %llu (max is %llu)", *rsp, MAX_STACK_MEMORY);
        #endif

        auto& s = *(uint16_t*) *rsp;
        s = *r;
        *rsp = *rsp + 2;

        #ifdef INSTRUCTION_DEBUG
          printf("PUSH2 %s (=0x%04x) (RSP 0x%016llx)\n", Register::get_name(m), s, (uint64_t) *rsp);
        #endif
      } break;

      case PUSH1: {
        auto& m = instructions[advance()];
        auto r  = (uint8_t*) op_registers.get_register(m);
        auto rsp = (uint8_t**) op_registers[Register::RSP];

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base < MAX_STACK_MEMORY - 1, "Stack Overflow: Cannot push 1 byte value to stack, RSP is %llu (max is %llu)", *rsp, MAX_STACK_MEMORY);
        #endif

        auto& s = **rsp;
        s = *r;
        *rsp = *rsp + 1;

        #ifdef INSTRUCTION_DEBUG
          printf("PUSH1 %s (=0x%02x) (RSP 0x%016llx)\n", Register::get_name(m), s, (uint64_t) *rsp);
        #endif
      } break;


      case CALL: {
        auto a = (uint64_t*) (instructions + advance(8));

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*a < instruction_length, "Cannot long jump to address %llu for CALL (from %llu), instruction range is 0 - %llu", *a, IP, instruction_length);
        #endif

        auto rsp = (uint8_t**) op_registers[Register::RSP];

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base < MAX_STACK_MEMORY - 8, "Stack Overflow: Cannot push 8 byte value to stack, RSP is %llu (max is %llu)", *rsp, MAX_STACK_MEMORY);
        #endif

        *(uint64_t*) *rsp = IP;
        *rsp = *rsp + 8;

        #ifdef INSTRUCTION_DEBUG
          printf("CALL %llu (from %llu)\n", *a, IP);
        #endif

        IP = *a;
      } break;

      case RET: {
        auto rsp = (uint8_t**) op_registers[Register::RSP];

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*rsp - stack_base >= 8, "Stack Underflow: Cannot pop 8 byte value from stack, RSP is only %llu", *rsp);
        #endif

        *rsp = *rsp - 8;
        
        auto a = (uint64_t*) *rsp;

        #ifdef INSTRUCTION_SAFE
          m_panic_assert(*a < instruction_length, "Cannot long jump to address %llu for RET (from %llu), instruction range is 0 - %llu", *a, IP, instruction_length);
        #endif

        #ifdef INSTRUCTION_DEBUG
          printf("RET %llu (from %llu)\n", *a, IP);
        #endif

        IP = *a;
      } break;


      case HALT: return false;


      default: m_panic_error("Unrecognized op code %u", op_code);
    }

    return true;
  }


  void run () {
    bool cont = true;
    do cont = execute();
    while (cont && IP < instruction_length);
  }
};


template <typename T>
uint8_t* encode_value (uint8_t*& dest, size_t& cap, size_t& len, T& v) {
  static constexpr
  size_t size = sizeof(T);

  size_t ncap = cap;
  
  while (ncap < len + size) ncap *= 2;
  
  if (cap < ncap) {
    cap = ncap;
    dest = (uint8_t*) realloc(dest, cap);
  }

  uint8_t* vp = dest + len;
  memcpy(dest + len, &v, size);

  len += size;

  return vp;
}

template <typename ... A>
Pair<uint8_t*, size_t> encode (A ... args) {
  auto data = (uint8_t*) malloc(16);
  size_t cap = 16;
  size_t len = 0;

  uint8_t* ps [] = { encode_value(data, cap, len, args)... };

  if (len < cap) data = (uint8_t*) realloc(data, len);

  return { data, len };
}


int main (int argc, char** args) {
  using namespace Instruction;
  using namespace Register;


  Interpreter I;


  constexpr int N = 34;

  auto fib = encode(
    LIT8, RCX, (uint64_t) N, //10
    LIT8, R8,  (uint64_t) 1, //10 + 10 = 20
    LIT8, R9,  (int64_t)  2, //20 + 10 = 30
    LIT8, R10, (int64_t) 16, //30 + 10 = 40


    CALL, (size_t) 50, // 9 + 40 = 49
    //PRINT8, RAX, // 49 + 2 = 51
    HALT, // 51 + 1 = 52 (-2 without print = 50)

    // fibonacci:
    CMP8, RCX, R8,
    JGT, (int64_t) 4, // return N if N <= 1
    MOV8, RAX, RCX,
    RET,

    ADD8, RSP, R10, // push 16 bytes
    STORE8, RSP, (int64_t) -16, RCX,  // save N
    
    SUB8, RCX, R8, // subtract 1
    CALL, (size_t) 50, // Compute N-1
    STORE8, RSP, (int64_t) -8, RAX, // save N-1

    LOAD8, RCX, RSP, (int64_t) -16, // restore N
    SUB8, RCX, R9, // subtract 2
    CALL, (size_t) 50, // Compute N-2

    LOAD8, RCX, RSP, (int64_t) -8, // restore N-1
    ADD8, RAX, RCX, // N-1 + N-2

    SUB8, RSP, R10, // pop 16 bytes

    RET
  );

  I.load(fib);

  
  typedef int (*fib_t) (int, void*);
  fib_t fib_s = [] (int n, void* f) {
    if (n <= 1) return n;
    else return ((fib_t ) f)(n - 1, f) + ((fib_t ) f)(n - 2, f);
  };

  
  I.run();
  printf("fib_i(%d) = %llu\n", N, *(uint64_t*) I.op_registers[RAX]);
  printf("fib_s(%d) = %d\n", N, fib_s(N, (void*) fib_s));


  I.clear();
  TimingResult timing_result = test_timing(10, 1000, [&] () { I.run(); }, [&] () { I.clear(); }, true, false);
  printf("Timing result: "); timing_result.print(10); putchar('\n');

  
  I.dispose(true);
}