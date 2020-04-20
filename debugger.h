#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <elf.h>
#include <pwd.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <capstone/capstone.h>

#define COMMAND_SIZE 100
#define MAX_BREAKPOINTS 500
#define USER_REGS_STRUCT_NO 27
#define PROCS_LENGTH 20
#define CURRENT_PERSONA 0xffffffff
#define OPCODES 8
#define EFLAGS 9

struct breakpoint_t
{
    char *symbol_name;
    long addr;
    long breakpoint;
    long hit;
};

struct eflags_t 
{
    char *name;
    uint16_t value;
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
void free_sym(struct breakpoint_t *, long);
void free_cmdargs(char **);

// elf parsing stuff
short check_type(Elf64_Ehdr *);
bool hasSections(Elf64_Ehdr *);
struct breakpoint_t *extract_symbols(Elf64_Ehdr *, char *, long *, char **);
long find_symbol_addr(struct breakpoint_t *, long, const char *);

// Modify process registers stuff
void copy_registers(unsigned long long *, struct user_regs_struct *);
void patch_regs(pid_t, struct user_regs_struct *, struct breakpoint_t *, long);
void modify_regs(unsigned long long *, struct user_regs_struct *);

// Tokenize user input stuff
void sep_tokens(char *, char **);

// display process registers and stack
void format_print(struct user_regs_struct *, struct user_regs_struct *, const char **, const struct eflags_t *);
void disassembly_view(pid_t, struct user_regs_struct *, struct breakpoint_t *, long);

// breakpoints stuff
long set_breakpoint(pid_t, long, struct breakpoint_t *, long);
void store_breakpoint(struct breakpoint_t *, long, long);
void resume_execution(pid_t, struct user_regs_struct *, struct breakpoint_t *, struct breakpoint_t *, long);

// info
void display_simbols(long, struct breakpoint_t *);
void display_breakpoints(struct breakpoint_t *);
void menu(void);

// get child base for dynamic binaries
long get_base(pid_t, struct breakpoint_t *, long);

// check child process features
void check_aslr(struct breakpoint_t *, long);

// function helpers (used in dissassembly opcodes func and inspect memory func)
void extract_bytes(uint8_t *, long);
void extract_gdb_words(uint32_t *, long, long);

// inspect memory
void peek_bytes_reg(pid_t, long, long, struct breakpoint_t *, long);
void peek_words_reg(pid_t, long, long, struct breakpoint_t *, long);