#include "Interpreter.hh"
#include "time.hh"

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
Program encode (A ... args) {
  auto data = (uint8_t*) malloc(16);
  size_t cap = 16;
  size_t len = 0;

  uint8_t* ps [] = { encode_value(data, cap, len, args)... };

  if (len < cap) data = (uint8_t*) realloc(data, len);

  return { data, len };
}


int main (int argc, char** args) {
  Interpreter I;

  using namespace Register;
  using namespace Instruction;

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

  I.load_program(fib);

  
  typedef int (*fib_t) (int, void*);
  fib_t fib_s = [] (int n, void* f) {
    if (n <= 1) return n;
    else return ((fib_t ) f)(n - 1, f) + ((fib_t ) f)(n - 2, f);
  };

  
  I.run();
  printf("fib_i(%d) = %llu\n", N, *(uint64_t*) I.op_registers + RAX);
  printf("fib_s(%d) = %d\n", N, fib_s(N, (void*) fib_s));
  
  
  // printf("Baseline speed test:\n");
  // TimingResult timing_result_s = test_timing(10, 1000, [&] () { fib_s(N, (void*) fib_s); });
  // printf("Baseline Timing result: "); timing_result_s.print(10); putchar('\n');


  I.clear();
  printf("Interpreter speed test:\n");
  TimingResult timing_result_i = test_timing(10, 1000, [&] () { I.run(); }, [&] () { I.clear(); }, true, false);
  printf("Interpreter Timing result: "); timing_result_i.print(10); putchar('\n');


  I.dispose();
}