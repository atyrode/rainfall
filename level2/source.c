#include <stdio.h>

void p(void)
{
  uint unaff_retaddr;
  char buffer[76];
  
  fflush(stdout);
  gets(buffer);
  if ((unaff_retaddr & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n", unaff_retaddr);
    _exit(1);
  }
  puts(buffer);
  strdup(buffer);
  return;
}

void main(void) {
  p();
  return;
}