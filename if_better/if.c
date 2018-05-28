#include <time.h>
#include <stdlib.h>
#include "WProtectSDK.h"

int main()
{
    srand(time(NULL));   // should only be called once
    int r = rand() % 2;      // returns a pseudo-random integer between 0 and RAND_MAX

    WProtectBegin();
    if (r == 1)
    {    __asm { inc eax };}
    else
    {    __asm { dec eax };}
    WProtectEnd();
    return 0;
}
