#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
int main(){
int ret;
    if ((ret=setreuid(65535, -1)) != 0)
    {
        printf("setreuid failed: %d\n", ret);
        return 0;
    }

}
