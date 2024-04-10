#include <stdlib.h>
#include <string.h>

void n()
{
    system("/bin/cat /home/user/level7/.pass");
    return;
}

void m()
{
    puts("Nope");
    return;
}

int main(int argc, char **argv) {
  char *string;
  void (**ptr2func_ptr)(void);

  string = (char *)malloc(64);
  ptr2func_ptr = (void (**)(void))malloc(4);

  *ptr2func_ptr = m;
  strcpy(string, argv[1]);
  (*ptr2func_ptr)();
}