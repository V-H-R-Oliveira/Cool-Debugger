#ifdef __linux__

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif

#define _GNU_SOURCE
#include <sys/personality.h>

#ifndef HAVE_PERSONALITY
#include <syscall.h>
#define personality(pers) ((long)syscall(SYS_personality, pers))
#endif

#ifndef ADDR_NO_RANDOMIZE
#define ADDR_NO_RANDOMIZE 0x40000
#endif

#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <pwd.h>
#include <sys/signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>

#define COMMAND_SIZE 100
#define MAX_BREAKPOINTS 500
#define USER_REGS_STRUCT_NO 27
#define PROCS_LENGTH 20
#define CURRENT_PERSONA 0xffffffff

struct breakpoint_t
{
    char *symbol_name;
    long addr;
    long breakpoint;
    long hit;
};

// process child preparation
bool disable_aslr(void);
char **extract_cmdline_args(int, char **);

// retrieve username from /etc/passwd stuff
char *username_from_uid(uid_t);

// file handle and memory stuff
void *map_file(const char *, long *);
void fclose_wrapper(FILE *);
void munmap_wrapper(void *, long);
void free_wrapper(void *);

// elf parsing stuff
short check_type(Elf64_Ehdr *);
bool hasSections(Elf64_Ehdr *);
struct breakpoint_t *extract_symbols(Elf64_Ehdr *, char *, long *);
long find_symbol_addr(struct breakpoint_t *, long, const char *);

// Modify process registers stuff
void copy_registers(unsigned long long *, struct user_regs_struct *);
void patch_regs(pid_t, struct user_regs_struct *, struct breakpoint_t *);
void modify_regs(unsigned long long *, struct user_regs_struct *);

// Tokenize user input stuff
void sep_tokens(char *, char **);

// display process registers stuff
void format_print(struct user_regs_struct *, struct user_regs_struct *, const char **);

// breakpoints stuff
long set_breakpoint(pid_t, long, struct breakpoint_t *);
void store_breakpoint(struct breakpoint_t *, long, long);
bool resume_execution(pid_t, struct user_regs_struct *, struct breakpoint_t *, struct breakpoint_t *);

// info
void display_simbols(long, struct breakpoint_t *);
void display_breakpoints(struct breakpoint_t *);
void menu(void);

// get child base for dynamic binaries
long get_base(struct breakpoint_t *, pid_t);

// check child process features
void check_aslr(struct breakpoint_t *);