#include "interpreter/Interpreter.hh"
#include "Assembler.hh"
#include "time.hh"


int main (int argc, char** args) {
  ti::Allocator A { 1024 * 1024 * 1024, 24 };
  ti::Interpreter I { &A };

  using namespace ti::Register;
  using namespace ti::InstructionBuilder;

  constexpr int N = 34;

  ti::Program fib = ti::PData {
    LIT8 { RCX, N },
    LIT8 { R8, 1 },
    LIT8 { R9, 2 },
    LIT8 { R10, 16 },

    CALL { "fib" },
    HALT,
    
  LABEL { "fib" },
    // Return N if N <= 1
    CMP8 { RCX, R8 },
    JGT { "fib_body" },
    MOV8 { RAX, RCX },
    RET,

  LABEL { "fib_body" },
    // Stack allocate and save N
    ADD8 { RSP, R10 },
    STORE8 { RSP, -16, RCX },

    // N - 1
    SUB8 { RCX, R8 }, // subtract 1
    CALL { "fib" }, // Compute N-1
    STORE8 { RSP, -8, RAX }, // save N-1
    
    // N - 2
    LOAD8 { RCX, RSP, -16 }, // restore N
    SUB8 { RCX, R9 }, // subtract 2
    CALL { "fib" }, // Compute N-2

    // Add results
    LOAD8 { RCX, RSP, -8 }, // restore N-1
    ADD8 { RAX, RCX }, // N-1 + N-2

    // Restore stack and return
    SUB8 { RSP, R10 },
    RET
  }.finalize(&A);

  I.load_program(fib);

  
  typedef int (*fib_t) (int, void*);
  fib_t fib_s = [] (int n, void* f) {
    if (n <= 1) return n;
    else return ((fib_t ) f)(n - 1, f) + ((fib_t ) f)(n - 2, f);
  };

  
  I.run();
  uint64_t fi = *(uint64_t*) (I.op_registers + RAX);
  uint64_t fs = fib_s(N, (void*) fib_s);
  printf("fib_i(%d) = %zu\n", N, fi);
  printf("fib_s(%d) = %zu\n", N, fs);
  m_panic_assert(fi == fs, "Bad result, expected %zu, not %zu", fs, fi);
  
  
  // printf("Baseline speed test:\n");
  // TimingResult timing_result_s = test_timing(10, 1, [&] () { fib_s(N, (void*) fib_s); });
  // printf("Baseline Timing result: "); timing_result_s.print(10); putchar('\n');


  I.clear();
  printf("Interpreter speed test:\n");
  TimingResult timing_result_i = test_timing(10, 1, [&] () { I.run(); }, [&] () { I.clear(); }, true, false);
  printf("Interpreter Timing result: "); timing_result_i.print(10); putchar('\n');


  I.dispose();
}