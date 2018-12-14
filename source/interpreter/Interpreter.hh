#pragma once

#include "base.h"
#include "Allocator.hh"


namespace ti {
  namespace Register {
    static constexpr
    uint8_t
      RAX = 0 * 8 + 0,
      RCX = 1 * 8 + 0,
      RDX = 2 * 8 + 0,
      RBX = 3 * 8 + 0,
      RSI = 4 * 8 + 0,
      RDI = 5 * 8 + 0,
      RSP = 6 * 8 + 0,
      RBP = 7 * 8 + 0,
      R8 = 8 * 8 + 0,
      R9 = 9 * 8 + 0,
      R10 = 10 * 8 + 0,
      R11 = 11 * 8 + 0,
      R12 = 12 * 8 + 0,
      R13 = 13 * 8 + 0,
      R14 = 14 * 8 + 0,
      R15 = 15 * 8 + 0,
      EAX = 0 * 8 + 4,
      ECX = 1 * 8 + 4,
      EDX = 2 * 8 + 4,
      EBX = 3 * 8 + 4,
      ESI = 4 * 8 + 4,
      EDI = 5 * 8 + 4,
      ESP = 6 * 8 + 4,
      EBP = 7 * 8 + 4,
      R8D = 8 * 8 + 4,
      R9D = 9 * 8 + 4,
      R10D = 10 * 8 + 4,
      R11D = 11 * 8 + 4,
      R12D = 12 * 8 + 4,
      R13D = 13 * 8 + 4,
      R14D = 14 * 8 + 4,
      R15D = 15 * 8 + 4,
      AX = 0 * 8 + 6,
      CX = 1 * 8 + 6,
      DX = 2 * 8 + 6,
      BX = 3 * 8 + 6,
      SI = 4 * 8 + 6,
      DI = 5 * 8 + 6,
      SP = 6 * 8 + 6,
      BP = 7 * 8 + 6,
      R8W = 8 * 8 + 6,
      R9W = 9 * 8 + 6,
      R10W = 10 * 8 + 6,
      R11W = 11 * 8 + 6,
      R12W = 12 * 8 + 6,
      R13W = 13 * 8 + 6,
      R14W = 14 * 8 + 6,
      R15W = 15 * 8 + 6,
      AL = 0 * 8 + 7,
      CL = 1 * 8 + 7,
      DL = 2 * 8 + 7,
      BL = 3 * 8 + 7,
      SIL = 4 * 8 + 7,
      DIL = 5 * 8 + 7,
      SPL = 6 * 8 + 7,
      BPL = 7 * 8 + 7,
      R8B = 8 * 8 + 7,
      R9B = 9 * 8 + 7,
      R10B = 10 * 8 + 7,
      R11B = 11 * 8 + 7,
      R12B = 12 * 8 + 7,
      R13B = 13 * 8 + 7,
      R14B = 14 * 8 + 7,
      R15B = 15 * 8 + 7;
  }


  namespace Comparison {
    enum: uint8_t {
      LT = (uint8_t) -1,
      EQ = 0,
      GT = 1
    };
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
    
    static constexpr
    uint8_t LABEL = INSTRUCTION_COUNT;
  }


  static constexpr size_t DEFAULT_STACK_SIZE = 1024*1024;


  extern "C" const char * REGISTER_NAMES [128];
  extern "C" uint8_t REGISTER_SIZES [128];
  extern "C" uint8_t INSTRUCTION_DATA_SIZES [Instruction::INSTRUCTION_COUNT];


  struct Interpreter;

  typedef struct {
    uint8_t* instructions;
    size_t instructions_length;
  } Program;


  // extern "C" void Interpreter_init_stack (Interpreter* i, size_t stack_size);
  extern "C" void Interpreter_clear (Interpreter* i);
  extern "C" void Interpreter_init (Interpreter* i, Allocator* allocator, size_t stack_size);
  // extern "C" Interpreter Interpreter_create (Allocator* allocator, size_t stack_size); // NOTE: (works but gives a warning, could create a cInterpreter struct with casting overloads but meh)
  extern "C" void Interpreter_dispose (Interpreter* i);
  extern "C" void Interpreter_load (Interpreter* i, uint8_t* instructions, size_t instructions_length);
  extern "C" void Interpreter_load_program (Interpreter* i, Program p);
  extern "C" void Interpreter_run (Interpreter* i);


  struct Interpreter {
    Allocator* allocator;

    uint8_t* instructions;
    uint8_t* max_instruction_address;

    uint8_t* stack;
    uint8_t* max_stack_address;

    uint8_t* op_registers;

    int8_t cmp;
    uint8_t* ip;
    

    inline Interpreter (Allocator* allocator) { Interpreter_init(this, allocator, DEFAULT_STACK_SIZE); }
    inline Interpreter (Allocator* allocator, size_t stack_size) { Interpreter_init(this, allocator, stack_size); }

    inline void dispose () { Interpreter_dispose(this); }

    inline void clear () { Interpreter_clear(this); }

    inline void load (uint8_t* instructions, size_t instructions_length) { Interpreter_load(this, instructions, instructions_length); }
    inline void load_program (Program& p) { Interpreter_load_program(this, p); }

    inline void run () { Interpreter_run(this); }
  };
}