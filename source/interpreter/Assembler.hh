#pragma once

#include "Interpreter.hh"

#include <vector>
#include <string>
#include <unordered_map>


namespace ti {
  static constexpr uint8_t MAX_LABEL_LENGTH = 64;

  struct LabelName {
    char data [MAX_LABEL_LENGTH];

    operator const char* () const { return data; }
    bool operator == (const LabelName& other) const { return strcmp(*this, other) == 0; }
  };


  inline
  uint64_t hash64 (const void* data, uint64_t size, uint64_t hash = 14695981039346656037llu) { 
    for (uint64_t i = 0; i < size; i ++) hash = (hash ^ ((uint8_t*) data)[i]) * 1099511628211llu;
    return hash;
  }
}


template<>
struct std::hash<ti::LabelName> {
  size_t operator () (const ti::LabelName& ln) const {
    return ti::hash64(ln.data, strlen(ln.data));
  }
};


namespace ti {
  template <typename T>
  using vec = ::std::vector<T>;
  template <typename K, typename V>
  using map = ::std::unordered_map<K, V>;

  struct None { };


  struct Encoder {
    uint8_t* data = (uint8_t*) malloc(16);
    size_t cap = 16;
    size_t len = 0;

    void dispose () {
      if (data != NULL) {
        free(data);
        data = NULL;
      }
      cap = 0;
      len = 0;
    }

    ~Encoder () {
      dispose();
    }

    uint8_t* encode_value (void* ptr, size_t size) {
      size_t ncap = cap;
      
      while (ncap < len + size) ncap *= 2;
      
      if (cap < ncap) {
        cap = ncap;
        data = (uint8_t*) realloc(data, cap);
      }

      uint8_t* vp = data + len;
      memcpy(vp, ptr, size);

      len += size;

      return vp;
    }

    template <typename T>
    uint8_t* encode_value (T& v) {
      return encode_value(&v, sizeof(T));
    }

    template <typename ... A>
    void encode (A ... args) {
      uint8_t* ps [] = { encode_value(args)... };
    }

    Program finalize () {
      uint8_t* out = data;
      uint64_t size = len;
      data = NULL;

      if (size < cap) out = (uint8_t*) realloc(out, len);

      dispose();
      
      return { out, size };
    }
  };


  struct Labelable {
    bool is_label;
    union {
      uint64_t address;
      LabelName label;
    };

    Labelable ()
    : is_label(false)
    , address(NULL)
    { }

    Labelable (uint64_t in_address)
    : is_label(false)
    , address(in_address)
    { }

    Labelable (const char* in_label)
    : is_label(true)
    {
      size_t len = strlen(in_label) + 1;
      m_panic_assert(len <= MAX_LABEL_LENGTH, "Cannot use %s as a label, max label length is %u", in_label, MAX_LABEL_LENGTH);
      memcpy(label.data, in_label, len);
    }

    void encode (Encoder* encoder, uint64_t instr_address, map<LabelName, uint64_t>* label_addresses, bool relative) {
      if (is_label) {
        uint64_t l_address = label_addresses->at(label);

        if (relative) encoder->encode((int64_t) l_address - (int64_t) instr_address); 
        else encoder->encode(l_address);
      } else {
        encoder->encode(address);
      }
    }
  };


  struct RegisterPair {
    uint8_t destination;
    uint8_t source;

    void encode (Encoder* encoder) {
      encoder->encode(destination, source);
    }
  };


  struct LoadSet {
    uint8_t destination;
    uint8_t source;
    int64_t source_offset;

    void encode (Encoder* encoder) {
      encoder->encode(destination, source, source_offset);
    }
  };


  struct StoreSet {
    uint8_t destination;
    int64_t destination_offset;
    uint8_t source;

    void encode (Encoder* encoder) {
      encoder->encode(destination, destination_offset, source);
    }
  };


  template <typename T>
  struct Literal {
    uint8_t destination;
    T value;
  };


  static constexpr
  uint8_t LABELABLE_COUNT = 9;

  static constexpr
  uint8_t LABELABLES [LABELABLE_COUNT] = {
    Instruction::LIT8,
    Instruction::JMP,
    Instruction::JEQ,
    Instruction::JNE,
    Instruction::JGE,
    Instruction::JLE,
    Instruction::JGT,
    Instruction::JLT,
    Instruction::CALL
  };


  struct LabelableLiteral {
    uint8_t destination;
    Labelable value;

    void encode (Encoder* encoder, uint64_t address, map<LabelName, uint64_t>* label_addresses, bool relative) {
      encoder->encode(destination);
      value.encode(encoder, address, label_addresses, relative);
    }
  };


  struct IData {
    uint8_t type;
    union {
      None NO_OP;

      LabelableLiteral LIT8;
      Literal<uint32_t> LIT4;
      Literal<uint16_t> LIT2;
      Literal<uint8_t> LIT1;
      
      uint8_t CLR8;
      uint8_t CLR4;
      uint8_t CLR2;
      uint8_t CLR1;
      
      RegisterPair MOV8;
      RegisterPair MOV4;
      RegisterPair MOV2;
      RegisterPair MOV1;
      
      RegisterPair ADD8;
      RegisterPair ADD4;
      RegisterPair ADD2;
      RegisterPair ADD1;

      RegisterPair SUB8;
      RegisterPair SUB4;
      RegisterPair SUB2;
      RegisterPair SUB1;
      
      RegisterPair CMP8;
      RegisterPair CMP4;
      RegisterPair CMP2;
      RegisterPair CMP1;

      Labelable JMP;
      Labelable JEQ;
      Labelable JNE;
      Labelable JGE;
      Labelable JLE;
      Labelable JGT;
      Labelable JLT;
      
      uint8_t PRINT8;
      uint8_t PRINT4;
      uint8_t PRINT2;
      uint8_t PRINT1;
      
      LoadSet LOAD8;
      LoadSet LOAD4;
      LoadSet LOAD2;
      LoadSet LOAD1;

      StoreSet STORE8;
      StoreSet STORE4;
      StoreSet STORE2;
      StoreSet STORE1;

      uint8_t PUSH8;
      uint8_t PUSH4;
      uint8_t PUSH2;
      uint8_t PUSH1;

      uint8_t POP8;
      uint8_t POP4;
      uint8_t POP2;
      uint8_t POP1;
      
      Labelable CALL;
      None RET;

      None HALT;

      LabelName LABEL;
    };


    void encode (Encoder* encoder, uint64_t address, map<LabelName, uint64_t>* label_addresses) {
      m_panic_assert(type <= Instruction::LABEL, "Cannot encode unrecognized instruction type %u", type);

      if (type == Instruction::LABEL) return;

      encoder->encode(type);

      uint64_t next_address = address + total_size();

      switch (type) {
        case Instruction::NO_OP:
        case Instruction::RET:
        case Instruction::HALT: return;


        case Instruction::LIT8:
          return LIT8.encode(encoder, next_address, label_addresses, false);

        case Instruction::CALL:
          return ((Labelable*) &NO_OP)->encode(encoder, next_address, label_addresses, false);

        case Instruction::JMP:
        case Instruction::JEQ:
        case Instruction::JNE:
        case Instruction::JGE:
        case Instruction::JLE:
        case Instruction::JGT:
        case Instruction::JLT:
          return ((Labelable*) &NO_OP)->encode(encoder, next_address, label_addresses, true);
        
        case Instruction::LIT4: case Instruction::LIT2: case Instruction::LIT1: {
          encoder->encode_value(&NO_OP, 1);

          if (type == Instruction::LIT4) {
            encoder->encode_value(&NO_OP + offsetof(Literal<uint32_t>, value), 4);
          } else if (type == Instruction::LIT2) {
            encoder->encode_value(&NO_OP + offsetof(Literal<uint16_t>, value), 2);
          } else if (type == Instruction::LIT1) {
            encoder->encode_value(&NO_OP + offsetof(Literal<uint8_t>, value), 1);
          }
        } return;
          

        case Instruction::CLR8: case Instruction::CLR4: case Instruction::CLR2: case Instruction::CLR1:
        case Instruction::PRINT8: case Instruction::PRINT4: case Instruction::PRINT2: case Instruction::PRINT1:
        case Instruction::PUSH8: case Instruction::PUSH4: case Instruction::PUSH2: case Instruction::PUSH1:
        case Instruction::POP8: case Instruction::POP4: case Instruction::POP2: case Instruction::POP1: {
          encoder->encode_value(&NO_OP, 1);
        } return;

        case Instruction::MOV8: case Instruction::MOV4: case Instruction::MOV2: case Instruction::MOV1:
        case Instruction::ADD8: case Instruction::ADD4: case Instruction::ADD2: case Instruction::ADD1:
        case Instruction::SUB8: case Instruction::SUB4: case Instruction::SUB2: case Instruction::SUB1:
        case Instruction::CMP8: case Instruction::CMP4: case Instruction::CMP2: case Instruction::CMP1:
          return ((RegisterPair*) &NO_OP)->encode(encoder);

        case Instruction::LOAD8: case Instruction::LOAD4: case Instruction::LOAD2: case Instruction::LOAD1:
          return ((LoadSet*) &NO_OP)->encode(encoder);

        case Instruction::STORE8: case Instruction::STORE4: case Instruction::STORE2: case Instruction::STORE1:
          return ((StoreSet*) &NO_OP)->encode(encoder);
      }
    }


    IData ()
    : type(0)
    , NO_OP { }
    { }

    IData (uint8_t in_type)
    : type(in_type)
    , NO_OP { }
    { }

    template <typename T>
    IData (const Literal<T>& in_lit)
    {
      static constexpr size_t size = sizeof(T);

      static_assert(size == 8 || size == 4 || size == 2 || size == 1);

      if constexpr (size == 8) {
        type = Instruction::LIT8;
        memcpy(&LIT8, &in_lit, 8);
      } else if constexpr (size == 4) {
        type = Instruction::LIT4;
        memcpy(&LIT4, &in_lit, 4);
      } else if constexpr (size == 2) {
        type = Instruction::LIT2;
        memcpy(&LIT2, &in_lit, 2);
      } else {
        type = Instruction::LIT1;
        memcpy(&LIT1, &in_lit, 1);
      }
    }

    template <typename T>
    IData (uint8_t in_type, const T& in_data)
    : type(in_type)
    {
      memcpy(&NO_OP, &in_data, sizeof(T));
    }

    IData (const char* in_label_name)
    : type(Instruction::LABEL)
    {
      size_t len = strlen(in_label_name) + 1;
      m_panic_assert(len <= MAX_LABEL_LENGTH, "Cannot create label with len %llu, max is %u", len, MAX_LABEL_LENGTH);
      memcpy(LABEL.data, in_label_name, len);
    }


    bool is_labelable () {
      for (uint8_t i = 0; i < LABELABLE_COUNT; i ++) {
        if (type == LABELABLES[i]) return true;
      }

      return false;
    }

    bool is_label () {
      return type == Instruction::LABEL;
    }

    uint8_t data_size () {
      if (type < Instruction::INSTRUCTION_COUNT) return INSTRUCTION_DATA_SIZES[type];
      else return 0;
    }

    uint8_t total_size () { 
      if (type < Instruction::INSTRUCTION_COUNT) return data_size() + 1;
      else return 0;
    }
  };


  namespace InstructionBuilders {
    static
    IData NO_OP;

    struct LIT8 : public IData {
      LIT8 (uint8_t r, const char* label) : IData (Instruction::LIT8, LabelableLiteral { r, { label } }) { }
      template <typename T>
      LIT8 (uint8_t r, const T& value) : IData (Instruction::LIT8, LabelableLiteral { r, { (uint64_t) value } }) { }
    };
    struct LIT4 : public IData { template <typename T> LIT4 (const T& v) : IData (Literal { v }) { } };
    struct LIT2 : public IData { template <typename T> LIT2 (const T& v) : IData (Literal { v }) { } };
    struct LIT1 : public IData { template <typename T> LIT1 (const T& v) : IData (Literal { v }) { } };

    struct CLR8 : public IData { CLR8 (uint8_t r) : IData (Instruction::CLR8, r) { } };
    struct CLR4 : public IData { CLR4 (uint8_t r) : IData (Instruction::CLR4, r) { } };
    struct CLR2 : public IData { CLR2 (uint8_t r) : IData (Instruction::CLR2, r) { } };
    struct CLR1 : public IData { CLR1 (uint8_t r) : IData (Instruction::CLR1, r) { } };

    struct MOV8 : public IData { MOV8 (uint8_t ra, uint8_t rb) : IData (Instruction::MOV8, RegisterPair { ra, rb }) { } };
    struct MOV4 : public IData { MOV4 (uint8_t ra, uint8_t rb) : IData (Instruction::MOV4, RegisterPair { ra, rb }) { } };
    struct MOV2 : public IData { MOV2 (uint8_t ra, uint8_t rb) : IData (Instruction::MOV2, RegisterPair { ra, rb }) { } };
    struct MOV1 : public IData { MOV1 (uint8_t ra, uint8_t rb) : IData (Instruction::MOV1, RegisterPair { ra, rb }) { } };

    struct ADD8 : public IData { ADD8 (uint8_t ra, uint8_t rb) : IData (Instruction::ADD8, RegisterPair { ra, rb }) { } };
    struct ADD4 : public IData { ADD4 (uint8_t ra, uint8_t rb) : IData (Instruction::ADD4, RegisterPair { ra, rb }) { } };
    struct ADD2 : public IData { ADD2 (uint8_t ra, uint8_t rb) : IData (Instruction::ADD2, RegisterPair { ra, rb }) { } };
    struct ADD1 : public IData { ADD1 (uint8_t ra, uint8_t rb) : IData (Instruction::ADD1, RegisterPair { ra, rb }) { } };
    struct SUB8 : public IData { SUB8 (uint8_t ra, uint8_t rb) : IData (Instruction::SUB8, RegisterPair { ra, rb }) { } };
    struct SUB4 : public IData { SUB4 (uint8_t ra, uint8_t rb) : IData (Instruction::SUB4, RegisterPair { ra, rb }) { } };
    struct SUB2 : public IData { SUB2 (uint8_t ra, uint8_t rb) : IData (Instruction::SUB2, RegisterPair { ra, rb }) { } };
    struct SUB1 : public IData { SUB1 (uint8_t ra, uint8_t rb) : IData (Instruction::SUB1, RegisterPair { ra, rb }) { } };
    struct CMP8 : public IData { CMP8 (uint8_t ra, uint8_t rb) : IData (Instruction::CMP8, RegisterPair { ra, rb }) { } };
    struct CMP4 : public IData { CMP4 (uint8_t ra, uint8_t rb) : IData (Instruction::CMP4, RegisterPair { ra, rb }) { } };
    struct CMP2 : public IData { CMP2 (uint8_t ra, uint8_t rb) : IData (Instruction::CMP2, RegisterPair { ra, rb }) { } };
    struct CMP1 : public IData { CMP1 (uint8_t ra, uint8_t rb) : IData (Instruction::CMP1, RegisterPair { ra, rb }) { } };

    struct JMP : public IData {
      JMP (const char* label) : IData (Instruction::JMP, Labelable { label }) { }
      JMP (int64_t address) : IData (Instruction::JMP, Labelable { (uint64_t) address }) { }
    };
    struct JEQ : public IData {
      JEQ (const char* label) : IData (Instruction::JEQ, Labelable { label }) { }
      JEQ (int64_t address) : IData (Instruction::JEQ, Labelable { (uint64_t) address }) { }
    };
    struct JNE : public IData {
      JNE (const char* label) : IData (Instruction::JNE, Labelable { label }) { }
      JNE (int64_t address) : IData (Instruction::JNE, Labelable { (uint64_t) address }) { }
    };
    struct JGE : public IData {
      JGE (const char* label) : IData (Instruction::JGE, Labelable { label }) { }
      JGE (int64_t address) : IData (Instruction::JGE, Labelable { (uint64_t) address }) { }
    };
    struct JLE : public IData {
      JLE (const char* label) : IData (Instruction::JLE, Labelable { label }) { }
      JLE (int64_t address) : IData (Instruction::JLE, Labelable { (uint64_t) address }) { }
    };
    struct JGT : public IData {
      JGT (const char* label) : IData (Instruction::JGT, Labelable { label }) { }
      JGT (int64_t address) : IData (Instruction::JGT, Labelable { (uint64_t) address }) { }
    };
    struct JLT : public IData {
      JLT (const char* label) : IData (Instruction::JLT, Labelable { label }) { }
      JLT (int64_t address) : IData (Instruction::JLT, Labelable { (uint64_t) address }) { }
    };

    struct PRINT8 : public IData { PRINT8 (uint8_t r) : IData (Instruction::PRINT8, r) { } };
    struct PRINT4 : public IData { PRINT4 (uint8_t r) : IData (Instruction::PRINT4, r) { } };
    struct PRINT2 : public IData { PRINT2 (uint8_t r) : IData (Instruction::PRINT2, r) { } };
    struct PRINT1 : public IData { PRINT1 (uint8_t r) : IData (Instruction::PRINT1, r) { } };

    struct LOAD8 : public IData { LOAD8 (uint8_t d, uint8_t s, int64_t o) : IData (Instruction::LOAD8, LoadSet { d, s, o }) { } };
    struct LOAD4 : public IData { LOAD4 (uint8_t d, uint8_t s, int64_t o) : IData (Instruction::LOAD4, LoadSet { d, s, o }) { } };
    struct LOAD2 : public IData { LOAD2 (uint8_t d, uint8_t s, int64_t o) : IData (Instruction::LOAD2, LoadSet { d, s, o }) { } };
    struct LOAD1 : public IData { LOAD1 (uint8_t d, uint8_t s, int64_t o) : IData (Instruction::LOAD1, LoadSet { d, s, o }) { } };

    struct STORE8 : public IData { STORE8 (uint8_t d, int64_t o, uint8_t s) : IData (Instruction::STORE8, StoreSet { d, o, s }) { } };
    struct STORE4 : public IData { STORE4 (uint8_t d, int64_t o, uint8_t s) : IData (Instruction::STORE4, StoreSet { d, o, s }) { } };
    struct STORE2 : public IData { STORE2 (uint8_t d, int64_t o, uint8_t s) : IData (Instruction::STORE2, StoreSet { d, o, s }) { } };
    struct STORE1 : public IData { STORE1 (uint8_t d, int64_t o, uint8_t s) : IData (Instruction::STORE1, StoreSet { d, o, s }) { } };

    struct PUSH8 : public IData { PUSH8 (uint8_t r) : IData (Instruction::PUSH8, r) { } };
    struct PUSH4 : public IData { PUSH4 (uint8_t r) : IData (Instruction::PUSH4, r) { } };
    struct PUSH2 : public IData { PUSH2 (uint8_t r) : IData (Instruction::PUSH2, r) { } };
    struct PUSH1 : public IData { PUSH1 (uint8_t r) : IData (Instruction::PUSH1, r) { } };

    struct POP8 : public IData { POP8 (uint8_t r) : IData (Instruction::POP8, r) { } };
    struct POP4 : public IData { POP4 (uint8_t r) : IData (Instruction::POP4, r) { } };
    struct POP2 : public IData { POP2 (uint8_t r) : IData (Instruction::POP2, r) { } };
    struct POP1 : public IData { POP1 (uint8_t r) : IData (Instruction::POP1, r) { } };

    struct CALL : public IData {
      CALL (const char* label) : IData (Instruction::CALL, Labelable { label }) { }
      CALL (uint64_t address) : IData (Instruction::CALL, Labelable { address }) { }
    };

    static
    IData RET { Instruction::RET };

    static
    IData HALT { Instruction::HALT };

    struct LABEL : public IData { LABEL (const char* label_name) : IData (label_name) { } };
  }


  struct PData {
    vec<IData> instruction_data;

    PData () = default;

    template <typename ... A>
    PData (A ... args)
    : instruction_data { args... }
    { }


    Program finalize () {
      Encoder encoder;

      uint64_t total_length = 0;
      uint64_t encoded_length = 0;

      map<LabelName, uint64_t> label_addresses;

      for (IData& instruction : instruction_data) {
        if (instruction.is_label()) {
          label_addresses.insert_or_assign(instruction.LABEL, total_length);
        } else total_length += instruction.total_size();
      }

      for (IData& instruction : instruction_data) {
        instruction.encode(&encoder, encoded_length, &label_addresses);

        encoded_length += instruction.total_size();
      }

      return encoder.finalize();
    }
  };
}