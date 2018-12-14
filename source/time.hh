#include <ctime>
#include <cstdint>
#include <cmath>
#include <cstdio>


template <typename T, typename ... A>
T min_num (T arg0, A ... args) {
  T min = arg0;
  T arg_arr [] = { args... };
  for (uint64_t i = 0; i < sizeof...(args); i ++) {
    if (arg_arr[i] < min) min = arg_arr[i];
  }
  return min;
}


namespace Internal {
  static constexpr
  uint64_t TEST_TIME_MAX_COUNT = 1024;
}


struct TimingResult {
  uint64_t count = 0;
  double times [Internal::TEST_TIME_MAX_COUNT] = { };
  double min_time = INFINITY;
  double max_time = -INFINITY;
  double total_time = 0;
  double average_time = 0;

  void print (int64_t max_count = -1) const {
    if (max_count == -1) max_count = this->count;
    max_count = min_num((uint64_t) max_count, (uint64_t) count, Internal::TEST_TIME_MAX_COUNT);
    printf(
      "{ count: %llu, min_time: %.6f, max_time: %.6f, average_time: %.6f, time list (Showing %llu/%llu): { ",
      this->count, this->min_time, this->max_time, this->average_time, max_count, this->count
    );
    for (uint64_t i = 0; i < max_count; i ++) {
      printf("%.6f", this->times[i]);
      if (i < max_count - 1) printf(", ");
    }
    printf(" } }");
  }
};


template <typename F, typename C = void(*)(), typename ... A>
TimingResult test_timing (uint64_t count, double unit, F test_function, C cleanup_function = [](){}, bool cleanup = false, bool cleanup_last = false, A& ... args) {
  // (unit 1000000.0 for microseconds, 1000 for milliseconds, 1 for seconds)

  // e.g. this prints ~1.01 because Sleep is inaccurate, the timing however, is on point
  // test_timing(1, 1.0, [](){ Sleep(1000); }).print(0);


  TimingResult result;
  result.count = min_num(count, Internal::TEST_TIME_MAX_COUNT);

  for (uint64_t i = 0; i < result.count; i ++) {
    clock_t t1, t2;

    printf("Performing timing test %llu / %llu\n", i + 1, result.count);
    
    t1 = clock();

    test_function(args ...);

    t2 = clock();

    if (cleanup) {
      if (cleanup_last || i < result.count - 1) cleanup_function();
    }

    // convert to unit
    double iteration_time = ((t2 - t1) / (double) CLOCKS_PER_SEC) * unit;

    result.times[i] = iteration_time;
    result.total_time += iteration_time;
    if (iteration_time < result.min_time) result.min_time = iteration_time;
    if (iteration_time > result.max_time) result.max_time = iteration_time;

    printf("Timing test completed in %lf\n", iteration_time);
  }

  result.average_time = result.total_time / result.count;

  return result;
}