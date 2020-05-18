
#include "param.h"
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fs.h"
#include "fcntl.h"
#include "syscall.h"
#include "traps.h"
#include "memlayout.h"



void
exampleHandler(int signum){
    printf(1,"i'm the handler! hello there signum: %d\n",signum);  
}


int
main(int argc, char *argv[]){
uint mask = 4;

struct sigaction act = {exampleHandler,0};
struct sigaction oldact;
if (sigaction(2,&act,&oldact) < 0){
    printf(1,"error on sigaction\n");
}
else {
    printf(1,"sigaction work properly on pid: %d\n",getpid());
}
kill(getpid(),2);
printf(1,"the mask should be: 0x%p\n",mask);
uint oldmask = sigprocmask(mask);
if (oldmask < 0){
    printf(1,"error on oldmask\n");
}
else{
    printf(1,"the oldmask is: 0x%p\t the newmask that set is: 0x%p\n\n",oldmask,mask);
}
printf(1,"should ignore and do not go to handler\n");
kill(getpid(),2);

kill(getpid(),2);


if (sigprocmask(0) >= 0){
    printf(1,"\t\tthe oldmask is: 0x%p\n\t\tthe newmask that set is: 0x%p\n\n",oldmask,0);
}

printf(1,"signal 2 ignored until now\n");
kill(getpid(),2);
act.sa_handler = (void*) SIG_IGN;
sigaction(2,&act,&oldact);
printf(1,"the newact is: 0x%p\n the oldact is SIG_IGN: 0x%p\n",act,oldact);
kill(getpid(),2);
act.sa_handler = (void*) SIG_DFL;
sigaction(2,&act,0);
printf(1,"the newact is DFL: 0x%p\n",act);



if (fork() == 0){
    sigprocmask(1<<9);
    kill(getpid(),9);
    printf(1,"ERROR!! you not sopposed to get here, the mask ignored kill bit\n");
}

//check default handler
if (fork() == 0){
    kill(getpid(),30);
    printf(1,"ERROR ! default handler doesn't work currently\n");
}

int cpid = fork();
if (cpid == 0){
    printf(1,"Child is alive \n");
    sleep(100);
    printf(1,"Child is alive again \n");
}
else
{
    kill(cpid,SIGSTOP);
    printf(1,"Parent stop Child\n");
    sleep(100);
    printf(1,"Parent alive again\n");
    kill(cpid,SIGCONT);
    sleep(100);
    printf(1,"finally come back to Parent\n");
}

wait();
wait();
wait();
exit();

}



