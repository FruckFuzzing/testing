#include <stdio.h>
#include <stdlib.h>
#include "mylib.h"
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
int main()
{
  const char *test_string = "TestCaseTest";
  int         result = 0;
  result = count_uppercase(test_string);

  printf("String: %s\n", test_string);
  printf("Uppercase letters count: %d\n", result);

  return 0;
}