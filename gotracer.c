#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static char **symnames = 0;
static void **symptrs = 0;
static size_t n_syms = 0;
static size_t capa_syms = 0;

#define PROGRAM "/home/kmeaw/src/ctf/tasks/ninja25519.elf"

const char *lookup(void *ptr, void ***out)
{
    int l = 0;
    int r = n_syms - 2; /* + "%eof." */
    int m;

    while (l < r)
    {
      m = (l + r) / 2;

      if (symptrs[m+1] < ptr)
        l = m + 1;
      else if (symptrs[m] > ptr)
        r = m - 1;
      else 
      {
        if (out)
          *out = &symptrs[m];
        return symnames[m];
      }
    }

    return NULL;
}

void load_symbols(char *programname)
{
    int s;
    FILE *fsym = NULL;

    void *sptr;
    char stype, sname[512];

    snprintf(sname, sizeof(sname) - 1, "nm %s | sort", programname);

    fsym = popen(sname, "r");
    if (!fsym)
    {
      perror("popen");
      abort();
    }

    do
    {
      s = fscanf(fsym, "%llx %c %511[^\n]s\n", (unsigned long long*) &sptr, &stype, sname);
      if (s <= 0)
      {
        sptr = (void *) -1;
        stype = 'X';
        strcpy (sname, "%eof.");
      }

      if (n_syms + 1 > capa_syms)
      {
        capa_syms = capa_syms ? 2 * capa_syms : 8;
        if (!(symnames = (char **) realloc (symnames, sizeof(char*) * capa_syms)))
        {
          perror ("realloc");
          abort();
        }

        if (!(symptrs = (void **) realloc (symptrs, sizeof(void*) * capa_syms)))
        {
          perror ("realloc");
          abort();
        }
      }

      symnames[n_syms] = strdup(sname);
      symptrs[n_syms] = sptr;
      n_syms++;
    } while (s > 0);

    printf("%zd symbols loaded.\n", n_syms);

    fclose (fsym);
}

int main(int argc, char **argv)
{
    pid_t child;

    if (argc < 2)
    {
      fprintf (stderr, "Usage: %s <program> [arguments…]\n", argv[0]);
      return 1;
    }

    load_symbols(argv[1]);

    puts ("Starting...");

    child = fork();
    if (child == 0) {
        setenv("GOMAXPROCS", "1", 1);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(argv[1], argv + 2);
    }
    else {
        int status;
        void **ptr = 0;
        const char *fn;
        void **stack;
        const char *caller;
        
        wait(&status);
        struct user_regs_struct regs;
        while (1) {
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if ((void *) regs.rip < symptrs[0])
              ;
            else if (!ptr || (void*) regs.rip < ptr[0] || (void*) regs.rip > ptr[1])
            {
              if ((fn = lookup((void *)regs.rip, &ptr)))
              {
                stack = (void **)regs.rsp;
                caller = lookup((void *) ptrace(PTRACE_PEEKTEXT, child, stack, 0), NULL);
                if (caller)
                {
                  printf("[%d] %s -> %s %p %p %p\n", child, caller, fn, ptr[0], (void*)regs.rip, ptr[1]);
                }
              }
            }
            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            waitpid(child, &status, 0);
            if(WIFEXITED(status)) break;
        }
        printf("end\n");
    }
    return 0;
}
