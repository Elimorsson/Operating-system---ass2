#define SIG_DFL 0
#define SIG_IGN 1

#define SIGKILL 9
#define SIGSTOP 17
#define SIGCONT 19

typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;
typedef uint pde_t;

struct sigaction {
    void (*sa_handler)(int);
    uint sigmask;
};
