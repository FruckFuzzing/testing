#include "mylib.h"
#include <ctype.h>

int count_uppercase(const char *str)
{
	int count = 0;
    while (*str){
        if(isupper(*str)){
            count++;
        }
        str++;
    }
    return count;
}