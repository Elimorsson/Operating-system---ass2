#include "syscall.h"
#include "traps.h"

.globl sigret_begin
.globl sigret_end

sigret_begin:
  movl $SYS_sigret, %eax
  int $T_SYSCALL
sigret_end: