#ifndef FOC_PROJECT_SRC_S3L_SIZECALCULATOR_H_
#define FOC_PROJECT_SRC_S3L_SIZECALCULATOR_H_

#include "../util.h"
#include <array>
#include <vector>

struct SizeCalculator {
  size_t size{};

  SizeCalculator() = default;

  template <typename A>
  friend SizeCalculator& operator<<(SizeCalculator& s,
                                    const std::vector<u8, A>& a) {
    s.size += a.size();
    return s;
  }

  template <typename A>
  friend SizeCalculator& operator<<(SizeCalculator&& s,
                                    const std::vector<u8, A>& a) {
    s.size += a.size();
    return s;
  }

  template <size_t N>
  friend SizeCalculator& operator<<(SizeCalculator& s,
                                    const std::array<u8, N>& a) {
    s.size += a.size();
    return s;
  }

  template <size_t N>
  friend SizeCalculator& operator<<(SizeCalculator&& s,
                                    const std::array<u8, N>& a) {
    s.size += a.size();
    return s;
  }

  friend SizeCalculator& operator<<(SizeCalculator& s,
                                    const std::integral auto& a) {
    s.size += sizeof(a);
    return s;
  }

  friend SizeCalculator& operator<<(SizeCalculator&& s,
                                    const std::integral auto& a) {
    s.size += sizeof(a);
    return s;
  }

  operator size_t() { return size; }
};

#endif  // FOC_PROJECT_SRC_S3L_SIZECALCULATOR_H_
