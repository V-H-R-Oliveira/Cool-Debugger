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
#include <unistd.h>
#include <elf.h>
#include <pwd.h>
#include <inttypes.h>
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

// retrieve username from /etc/passwd
char *username_from_uid(uid_t);

// file handle and memory
void *map_file(const char *, long *);
void fclose_wrapper(FILE *);
void munmap_wrapper(void *, long);
void free_sym(struct breakpoint_t *, const long);
void free_cmdargs(char **);

// elf parsing
bool isElf(const char *);
bool is_x86_64(const Elf64_Ehdr *);
short check_type(const Elf64_Ehdr *);
bool hasSections(const Elf64_Ehdr *);
struct breakpoint_t *extract_symbols(const Elf64_Ehdr *, char *, long *, char **);
long find_symbol_addr(const struct breakpoint_t *, const long, const char *);

// Modify process registers
void copy_registers(unsigned long long *, struct user_regs_struct *);
void patch_regs(const pid_t, struct user_regs_struct *, struct breakpoint_t *, const long);
void modify_regs(unsigned long long *, struct user_regs_struct *);

// Tokenize user input
void sep_tokens(char *, char **);

// display process registers and stack
void format_print(struct user_regs_struct *, struct user_regs_struct *, const char **, const struct eflags_t *);
void disassembly_view(const pid_t, struct user_regs_struct *, struct breakpoint_t *, const long);

// breakpoints
long set_breakpoint(const pid_t, const long, struct breakpoint_t *, const long);
void store_breakpoint(struct breakpoint_t *, long, long);
void resume_execution(const pid_t, struct user_regs_struct *, struct breakpoint_t *, struct breakpoint_t *, const long);

// info about the current process
void menu(void);
void display_man(char *);
void check_feature(char *, struct breakpoint_t *, const long);
void display_process_info(char *, const struct breakpoint_t *, const struct breakpoint_t *, const long);
void display_simbols(const struct breakpoint_t *, const long);
void display_breakpoints(const struct breakpoint_t *);

// get child base for dynamic binaries
long get_base(const pid_t, struct breakpoint_t *, const long);

// check child process features
void check_aslr(struct breakpoint_t *, const long);

void set_command(const pid_t, char *, const char **, unsigned long long *, struct user_regs_struct *, struct breakpoint_t *, const long);
void bp_command(const pid_t, char *, struct breakpoint_t *, const short, const long, struct breakpoint_t *, const long);

// function helpers (used in dissassembly opcodes func and inspect memory func)
void extract_bytes(uint8_t *, long);
void extract_gdb_words(uint32_t *, long, long);

// inspect memory
void inspect_memory(const pid_t, char *, struct breakpoint_t *, const long, const char **, const short, const long);
void peek_bytes(const pid_t, long, long, struct breakpoint_t *, const long);
void peek_words(const pid_t, long, long, struct breakpoint_t *, const long);