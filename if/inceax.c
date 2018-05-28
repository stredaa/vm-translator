#include <stdio.h>
#include "WProtectSDK.h"

int main()
{
    WProtectBegin();
    int a = 0;
    
    if (a == 0)
    {    __asm { inc eax };}
    else
    {    __asm { dec eax };}
    
    a = 1;
    
    if (a == 0)
    {    __asm { inc eax };}
    else
    {    __asm { dec eax };}
    WProtectEnd();
    return 0;
}
