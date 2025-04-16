#include "CDebugging.h"

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>

#if defined(_WIN32) || defined(_WIN64)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <debugapi.h>
#endif

void
CDebugging_Assert(
  const char *const a_File,
  const char *const a_Function,
  const uint64_t a_Line,
  const char *const a_Expression,
  ...
)
{
  va_list args;
  va_start(args, a_Expression);
  const char *const a_Message = va_arg(args, char *);
  fprintf_s(stderr, "%s:%llu Assertion failed in %s", a_File, a_Line, a_Function, a_Expression);
  if(a_Message != NULL) { fprintf_s(stderr, " (%s)", a_Message); }
  fprintf_s(stderr, "\n");
  va_end(args);
  CDebugging_Abort();
}

void
CDebugging_Abort()
{
#if defined(_WIN32) || defined(_WIN64)
  DebugBreak();
#elif defined(__linux__)
  raise(SIGTRAP);
#endif
  raise(SIGABRT);
}

void
CDebuggingBreakpoint_Set(
  CDebuggingBreakpoint *a_Breakpoint,
  const char *const a_File,
  const char *const a_Function,
  const uint64_t a_Line
)
{
  assert(a_Breakpoint != NULL);
  if(setjmp(a_Breakpoint->m_JumpSite.m_Buffer) == 0)
  {
    a_Breakpoint->m_Armed = true;
    a_Breakpoint->m_SetSite.m_File = a_File;
    a_Breakpoint->m_SetSite.m_Function = a_Function;
    a_Breakpoint->m_SetSite.m_Line = a_Line;
  }
  else
  {
    fprintf_s(
      stderr,
      "Breakpoint set in %s:%s at %llu triggered in %s:%s at %llu\n",
      a_Breakpoint->m_SetSite.m_File,
      a_Breakpoint->m_SetSite.m_Function,
      a_Breakpoint->m_SetSite.m_Line,
      a_Breakpoint->m_JumpSite.m_File,
      a_Breakpoint->m_JumpSite.m_Function,
      a_Breakpoint->m_JumpSite.m_Line
    );
    CDebugging_Abort();
  }
}

void
CDebuggingBreakpoint_Break(
  CDebuggingBreakpoint *a_Breakpoint,
  const char *const a_File,
  const char *const a_Function,
  const uint64_t a_Line
)
{
  assert(a_Breakpoint != NULL);
  if(a_Breakpoint->m_Armed)
  {
    a_Breakpoint->m_Armed = false;
    a_Breakpoint->m_JumpSite.m_File = a_File;
    a_Breakpoint->m_JumpSite.m_Function = a_Function;
    a_Breakpoint->m_JumpSite.m_Line = a_Line;
    longjmp(a_Breakpoint->m_JumpSite.m_Buffer, 1);
  }
}

void
CDebuggingBreakpoint_Clear(
  CDebuggingBreakpoint *a_Breakpoint
)
{
  assert(a_Breakpoint != NULL);
  a_Breakpoint->m_Armed = false;
  memset(&a_Breakpoint->m_JumpSite.m_Buffer, 0, sizeof(a_Breakpoint->m_JumpSite.m_Buffer));
  memset(&a_Breakpoint->m_SetSite, 0, sizeof(a_Breakpoint->m_SetSite));
  memset(&a_Breakpoint->m_JumpSite, 0, sizeof(a_Breakpoint->m_JumpSite));
}
