#include "types.h"
#include "stat.h"
#include "user.h"
#include "x86.h"


int
main(int argc, char *argv[])
{
  int a, b, c,ret;
  a = 1; b = 2; c = 3;
  int i=1;
  printf(1,"a %d b %d c %d\n",a,b,c);
  ret = cas(&a,b,c);
  printf(1,"ret %d, a %d \n\n",ret, a);
  if(ret){
    printf(1,"Case %d Fail\n ",i);
    exit();
  }
  i++;
  a = 2; b = 2; c = 3;
  
  printf(1,"a %d b %d c %d\n",a,b,c);
  ret = cas(&a,b,c);
  printf(1,"ret %d, a %d \n\n",ret, a);
  if(!ret){
    printf(1,"Case %d Fail\n ",i);
    exit();
  }
  i++;
  a = 3; b = 2; c = 3;
  
  printf(1,"a %d b %d c %d\n",a,b,c);
  ret = cas(&a,b,c);
  printf(1,"ret %d, a %d \n\n",ret, a);
  if(ret){
    printf(1,"Case %d Fail\n ",i);
    exit();
  }
  i++;
  a = 3; b = 3; c = 30;
  
  printf(1,"a %d b %d c %d\n",a,b,c);
  ret = cas(&a,b,c);
  printf(1,"ret %d, a %d \n\n",ret, a);
  if(!ret){
    printf(1,"Case %d Fail\n ",i);
    exit();
  }
  i++;
  a = 2; b = 4; c = 3;
  
  printf(1,"a %d b %d c %d\n",a,b,c);
  ret = cas(&a,b,c);
  printf(1,"ret %d, a %d \n\n",ret, a);
  if(ret){
    printf(1,"Case i %d Fail\n ",i);
    exit();
  }
  i++;
   a = 3; b = 4; c = 30;
  
  printf(1,"a %d b %d c %d\n",a,b,c);
  ret = cas(&a,b,c);
  printf(1,"ret %d, a %d \n\n",ret, a);
  if(ret){
    printf(1,"Case %d Fail\n ",i);
    exit();
  }
  i++;
   a = 4; b = 4; c = 30;
  
  printf(1,"a %d b %d c %d\n",a,b,c);
  ret = cas(&a,b,c);
  printf(1,"ret %d, a %d \n\n",ret, a);
  if(!ret){
    printf(1,"Case %d Fail\n ",i);
    exit();
  }
  printf(1,"All Tests passed\n");
  exit();
}
