void __noreturn o()
{
  system("/bin/sh");
  _exit(1);
}

void __noreturn n()
{
  char s[520]; // [esp+10h] [ebp-208h] BYREF

  fgets(s, 512, stdin);
  printf(s);
  exit(1);
}