#include <stdio.h>

int m;

void v(void)

{
  char buffer[520];
  
  fgets(buffer, 512, stdin);
  printf(buffer);
  if (m == 0x40) {
    fwrite("Wait what?!\n", 1, 0xc, stdout);
    system("/bin/sh");
  }
  return;
}

void main() { 
    v(); 
    return;
}
