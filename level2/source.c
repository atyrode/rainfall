void p()
{
  uint unaff_retaddr;
  char buffer[76];
  
  fflush(stdout);
  gets(buffer);
  if ((unaff_retaddr & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n",unaff_retaddr);
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
  puts(buffer);
  strdup(buffer);
  return;
}

int main() { v(); return 0;}