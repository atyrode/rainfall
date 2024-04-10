#include <stdio.h>

void    p() {
  char buffer[64];
  int retaddr;

  fflush(stdout);
  gets(buffer);
  retaddr = *((int*)(&buffer + 80));
  if ( (retaddr & 0xb0000000) == 0xb0000000 ) {
    printf("(%p)\n", retaddr);
    exit(1);
  }
  puts(buffer);
  strdup(buffer);
  return;
}

int	main()
{
	p();
	return (0);
}