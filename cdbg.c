#include "cdbg.h"

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <debugapi.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
#  define cdbg_fprintf fprintf_s
#else
#  define cdbg_fprintf fprintf
#endif

void
cdbg_assert(
  const char *const a_file,
  const char *const a_function,
  uint64_t a_line,
  const char *const a_expression,
  bool a_abort,
  ...
)
{
  va_list l_args;
  va_start(l_args, a_abort);
  const char *const l_message = va_arg(l_args, char *);
  cdbg_fprintf(stderr, "%s:%llu Assertion failed in %s", a_file, a_line, a_function, a_expression);
  if(l_message != NULL) { cdbg_fprintf(stderr, " (%s)", l_message); }
  cdbg_fprintf(stderr, "\n");
  va_end(l_args);
  if(a_abort) { cdbg_abort(); }
}

void
cdbg_abort()
{
#if defined(_WIN32) || defined(_WIN64)
  DebugBreak();
#elif defined(__linux__)
  raise(SIGTRAP);
#endif
  raise(SIGABRT);
}

void
cdbg_breakpoint_set(
  cdbg_breakpoint_t *a_breakpoint,
  const char *const a_file,
  const char *const a_function,
  uint64_t a_line
)
{
  assert(a_breakpoint != NULL);
  if(setjmp(a_breakpoint->m_jump_site.m_buffer) == 0)
  {
    a_breakpoint->m_armed = true;
    a_breakpoint->m_set_site.m_file = a_file;
    a_breakpoint->m_set_site.m_function = a_function;
    a_breakpoint->m_set_site.m_line = a_line;
  }
  else
  {
    cdbg_fprintf(
      stderr,
      "Breakpoint set in %s:%s at %llu triggered in %s:%s at %llu\n",
      a_breakpoint->m_set_site.m_file,
      a_breakpoint->m_set_site.m_function,
      a_breakpoint->m_set_site.m_line,
      a_breakpoint->m_jump_site.m_file,
      a_breakpoint->m_jump_site.m_function,
      a_breakpoint->m_jump_site.m_line
    );
    cdbg_abort();
  }
}

void
cdg_breakpoint_break(
  cdbg_breakpoint_t *a_breakpoint,
  const char *const a_file,
  const char *const a_function,
  uint64_t a_line
)
{
  assert(a_breakpoint != NULL);
  if(a_breakpoint->m_armed)
  {
    a_breakpoint->m_armed = false;
    a_breakpoint->m_jump_site.m_file = a_file;
    a_breakpoint->m_jump_site.m_function = a_function;
    a_breakpoint->m_jump_site.m_line = a_line;
    longjmp(a_breakpoint->m_jump_site.m_buffer, 1);
  }
}

void
cdbg_breakpoint_clear(
  cdbg_breakpoint_t *a_breakpoint
)
{
  assert(a_breakpoint != NULL);
  a_breakpoint->m_armed = false;
  memset(
    &a_breakpoint->m_jump_site.m_buffer, 0, sizeof(a_breakpoint->m_jump_site.m_buffer)
  );
  memset(&a_breakpoint->m_set_site, 0, sizeof(a_breakpoint->m_set_site));
  memset(&a_breakpoint->m_jump_site, 0, sizeof(a_breakpoint->m_jump_site));
}
