#include "types.h"
#include "stat.h"
#include "user.h"



int
main(int argc, char **argv)
{
  

  if(argc < 3){
    printf(2, "usage: kill pid...\n");
    exit();
  }
  int pid = atoi(argv[1]);
  int signum = atoi(argv[2]);
  kill(pid, signum);
  exit();
}
