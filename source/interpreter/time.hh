#include "../standard/lib.hh"
#include "windows.h"
using u64 = stdl::u64;
using s64 = stdl::s64;
using f64 = stdl::f64;

namespace Internal {
  static constexpr
  u64 TEST_TIME_MAX_COUNT = 1024;
}

struct TimingResult {
  u64 count = 0;
  f64 times [Internal::TEST_TIME_MAX_COUNT] = { };
  f64 min_time = INFINITY;
  f64 max_time = -INFINITY;
  f64 total_time = 0;
  f64 average_time = 0;

  void print (s64 max_count = -1) const {
    if (max_count == -1) max_count = this->count;
    max_count = stdl::min_num((u64) max_count, (u64) count, Internal::TEST_TIME_MAX_COUNT);
    printf(
      "{ count: %llu, min_time: %.6f, max_time: %.6f, average_time: %.6f, time list (Showing %llu/%llu): { ",
      this->count, this->min_time, this->max_time, this->average_time, max_count, this->count
    );
    for (u64 i = 0; i < max_count; i ++) {
      printf("%.6f", this->times[i]);
      if (i < max_count - 1) printf(", ");
    }
    printf(" } }");
  }
};

template <typename F, typename C = void(*)(), typename ... A>
TimingResult test_timing (u64 count, f64 unit, F test_function, C cleanup_function = [](){}, bool cleanup = false, bool cleanup_last = false, A& ... args) {
  // (unit 1000000.0 for microseconds, 1000 for milliseconds, 1 for seconds)

  // e.g. this prints ~1.01 because Sleep is inaccurate, the timing however, is on point
  // test_timing(1, 1.0, [](){ Sleep(1000); }).print(0);

  LARGE_INTEGER frequency;
  QueryPerformanceFrequency(&frequency);

  TimingResult result;
  result.count = stdl::min_num(count, Internal::TEST_TIME_MAX_COUNT);

  for (u64 i = 0; i < result.count; i ++) {
    LARGE_INTEGER t1, t2;

    printf("Performing timing test %llu / %llu\n", i + 1, result.count);
    
    QueryPerformanceCounter(&t1);

    test_function(args ...);

    QueryPerformanceCounter(&t2);

    if (cleanup) {
      if (cleanup_last || i < result.count - 1) cleanup_function();
    }

    // convert to milliseconds
    f64 iteration_time = (t2.QuadPart - t1.QuadPart) * unit / frequency.QuadPart;

    result.times[i] = iteration_time;
    result.total_time += iteration_time;
    if (iteration_time < result.min_time) result.min_time = iteration_time;
    if (iteration_time > result.max_time) result.max_time = iteration_time;

    printf("Timing test completed in %lf\n", iteration_time);
  }

  result.average_time = result.total_time / result.count;

  return result;
}