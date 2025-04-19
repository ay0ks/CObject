#pragma once

#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>

#define assert($Expression, ...)                                               \
  ((void)((!!($Expression))                                                    \
          || (cdbg_assert(__FILE__, __func__, __LINE__, #$Expression, __VA_ARGS__))))

#define assert_equals($Left, $Right, ...)                                      \
  ((void)((!!($Left == $Right))                                                \
          || (cdbg_assert(__FILE__, __func__, __LINE__, #$Left " == " #$Right, __VA_ARGS__))))

void
cdbg_assert(
  const char *ac_file,
  const char *ac_function,
  const uint64_t ac_line,
  const char *ac_expression,
  ...
);

void
cdbg_abort();

typedef struct cdbg_breakpoint_s
{
  bool m_armed;
  struct
  {
    const char *mc_file;
    const char *mc_function;
    const uint64_t mc_line;
  } m_set_site;
  struct
  {
    jmp_buf m_buffer;
    const char *mc_file;
    const char *mc_function;
    const uint64_t mc_line;
  } m_jump_site;
} cdbg_breakpoint_t;

void
cdbg_breakpoint_set(
  cdbg_breakpoint_t *a_breakpoint,
  const char *ac_file,
  const char *ac_function,
  const uint64_t ac_line
);

void
cdbg_breakpoint_break(
  cdbg_breakpoint_t *a_breakpoint,
  const char *ac_file,
  const char *ac_function,
  const uint64_t ac_line
);

void
cdbg_breakpoint_clear(cdbg_breakpoint_t *a_breakpoint);

#define breakpoint_set($Breakpoint)                                            \
  (cdbg_breakpoint_set($Breakpoint, __FILE__, __func__, __LINE__))

#define breakpoint_trigger($Breakpoint)                                        \
  (cdbg_breakpoint_break($Breakpoint, __FILE__, __func__, __LINE__))

#define breakpoint_clear($Breakpoint) (cdbg_breakpoint_clear($Breakpoint))
