#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif

#ifdef __linux__
#define _GNU_SOURCE
#include <sys/personality.h>

#ifndef HAVE_PERSONALITY
#include <syscall.h>
#define personality(pers) ((long)syscall(SYS_personality, pers))
#endif

#ifndef ADDR_NO_RANDOMIZE
#define ADDR_NO_RANDOMIZE 0x0040000
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
static inline bool disable_aslr(void);

// retrieve username from /etc/passwd stuff
char *username_from_uid(uid_t);

// file handle stuff
void *map_file(const char *, long *);
void fclose_wrapper(FILE *);
void munmap_wrapper(void *, long);
short check_type(Elf64_Ehdr *);
bool hasSections(Elf64_Ehdr *);
struct breakpoint_t *extract_symbols(Elf64_Ehdr *, char *, long *);
long find_symbol_addr(long, const char *);
void free_sym(void);

// Modify process registers stuff
void copy_registers(unsigned long long *, struct user_regs_struct *);
void patch_regs(pid_t, struct user_regs_struct *);
void modify_regs(unsigned long long *, struct user_regs_struct *);

// Tokenize user input stuff
void sep_tokens(char *, char **);

// display process registers stuff
void format_print(struct user_regs_struct *, struct user_regs_struct *, const char **);

// breakpoints stuff
long set_breakpoint(pid_t, long);
void store_breakpoint(struct breakpoint_t *, long, long);
bool resume_execution(pid_t, struct user_regs_struct *, struct breakpoint_t *);

// info
void display_simbols(long);
void display_breakpoints(struct breakpoint_t *);
static inline void menu(void);
// get child base for dynamic binaries
long get_base(pid_t);

// check child process features

void check_aslr(void);

extern char **environ;
static struct breakpoint_t *file_symbols;

/*
    Implementar o dissasembler usando capstone
*/

int main(int argc, char **argv)
{
    menu();   

    if (argc != 2)
    {
        fprintf(stderr, "Usage %s <file>\n", *argv);
        return 1;
    }

    char buffer[COMMAND_SIZE] = {'\0'};
    unsigned long long reg_cpy[USER_REGS_STRUCT_NO] = {0};
    const char *registers[] = {
        "r15",
        "r14",
        "r13",
        "r12",
        "rbp",
        "rbx",
        "r11",
        "r10",
        "r9",
        "r8",
        "rax",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "orig_rax",
        "rip",
        "cs",
        "eflags",
        "rsp",
        "ss",
        "fs_base",
        "gs_base",
        "ds",
        "es",
        "fs",
        "gs",
    };

    const char *path = argv[1];
    char *args[2];
    long length = 0, symtab_size = 0, base = 0;
    char *content = map_file(path, &length);
    pid_t pid = 0;
    struct user_regs_struct regs, saved = regs;
    int status = 0;
    struct breakpoint_t breakpoints[MAX_BREAKPOINTS];
    Elf64_Ehdr *elf_headers;
    short elf_type = 0;
    bool first_time = true; // gambiarra, famosa sentinela

    if (*content != 0x7f && strncmp(&content[0], "ELF", 3) != 0)
    {
        fprintf(stderr, "%s isn't an elf...\n", path);
        munmap_wrapper(content, length);
        return 1;
    }

    elf_headers = (Elf64_Ehdr *)content;
    *args = strdup(argv[1]);

    if (!(*args))
    {
        munmap_wrapper(content, length);
        perror("strdup error: ");
        return 1;
    }

    args[1] = NULL;
    elf_type = check_type(elf_headers);

    file_symbols = extract_symbols(elf_headers, content, &symtab_size);
    munmap_wrapper(content, length);

    if (!disable_aslr())
        puts("Not able to disable ASLR :(");

    pid = fork();

    if (pid == -1)
    {
        free_sym();
        perror("fork error: ");
        return 1;
    }

    if (pid == 0) // child
    {
        if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) == -1)
        {
            free_sym();
            perror("ptrace TRACEME error: ");
            return 1;
        }

        if (execve(*args, args, environ) == -1)
        {
            free_sym();
            perror("execve error: ");
            return 1;
        }

        return 0;
    }

    memset(&breakpoints, 0, sizeof(struct breakpoint_t) * MAX_BREAKPOINTS);

    printf("[\x1B[96m%ld\x1B[0m] Init session....\n", (long)pid);

    for (;;)
    {
        if (wait(&status) == -1)
        {
            free_sym();
            perror("wait error: ");
            return 1;
        }

        if (WIFEXITED(status))
        {
            free_sym();
            break;
        }

        if (elf_type == 2 && first_time)
        {
            base = get_base(pid);
            first_time = false;
        }

        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
        {
            free_sym();
            perror("ptrace GETREGS error: ");
            return 1;
        }

        format_print(&regs, &saved, registers);

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        {
            if (resume_execution(pid, &regs, breakpoints))
                goto prompt_label;
        }

        copy_registers(reg_cpy, &regs);
        saved = regs;

        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
        {
            free_sym();
            perror("ptrace SINGLESTEP error: ");
            return 1;
        }

    prompt_label:
        printf("[\x1B[96m0x%llx\x1B[0m]> ", regs.rip);
        fflush(NULL);

        if (!fgets(buffer, COMMAND_SIZE, stdin))
        {
            free_sym();
            perror("fgets error: ");
            return 1;
        }

        if ((strlen(buffer) - 1) == 1)
        {
            switch (*buffer)
            {
            case 's':
                continue;
                break;
            case 'c':
            {
                if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
                {
                    free_sym();
                    perror("ptrace CONT error: ");
                    return 1;
                }
                break;
            }
            case 'q':
            {
                free_sym();
                goto end;
                break;
            }
            default:
                puts("\x1B[01;93mHint\x1B[0m: man cmd");
                goto prompt_label;
                break;
            }
        }
        else
        {
            if (strstr(buffer, "man") != NULL)
            {
                char *tokens = strtok(buffer, " ");
                char *args[2];

                sep_tokens(tokens, args);

                char *info = args[1];

                if (!info)
                {
                    puts("man <info/bp/set/cmd/check>");
                    goto prompt_label;
                }

                if (strncmp(info, "info", 3) == 0) // info
                    puts("info <bp/sym>");
                else if (strncmp(info, "bp", 2) == 0) // breakpoints
                    puts("bp <symbol/*address>");
                else if (strncmp(info, "set", 3) == 0) // set
                    puts("set <$register>=<$register/value>");
                else if (strncmp(info, "cmd", 3) == 0)
                    puts("\x1B[96mDebugger commands:\x1B[0m\nc -> continue\ns -> single step\nq -> quit");
                else if (strncmp(info, "check", 5) == 0)
                    puts("check <aslr>");
            }
            else if (strstr(buffer, "check") != NULL)
            {
                char *tokens = strtok(buffer, " ");
                char *args[2];

                sep_tokens(tokens, args);

                char *info = args[1];

                if (!info)
                {
                    puts("\x1B[01;93mHint\x1B[0m: man check");
                    goto prompt_label;
                }

                if (strncmp(info, "aslr", 4) == 0)
                    check_aslr();
                else
                {
                    puts("\x1B[01;93mHint\x1B[0m: man check");
                    goto prompt_label;
                }
            }
            else if (strstr(buffer, "info") != NULL)
            {
                char *tokens = strtok(buffer, " ");
                char *args[2];

                sep_tokens(tokens, args);

                char *info = args[1];

                if (!info)
                {
                    puts("\x1B[01;93mHint\x1B[0m: man info");
                    goto prompt_label;
                }

                if (strncmp(info, "sym", 3) == 0) // símbolos
                    display_simbols(symtab_size);
                else if (strncmp(info, "bp", 2) == 0) // breakpoints
                    display_breakpoints(breakpoints);
                else
                {
                    puts("\x1B[01;93mHint\x1B[0m: man info");
                    goto prompt_label;
                }
            }
            else if (strstr(buffer, "set") != NULL)
            {
                char *tokens = strtok(buffer, " ");
                char *args[2];

                sep_tokens(tokens, args);
                tokens = strtok(args[1], "=");
                sep_tokens(tokens, args);

                char *dst = *args;
                char *src = args[1];

                if (*dst == '$')
                {
                    if (*src != '$') // valor
                    {
                        long val = strtol(src, NULL, 16);
                        dst++;
                        short dst_op = -1;

                        // // locate and patch the correct value

                        for (short i = 0; i < USER_REGS_STRUCT_NO; ++i)
                        {
                            if (strncmp(registers[i], dst, 3) == 0)
                            {
                                dst_op = i;
                                break;
                            }
                        }

                        if (dst_op == -1)
                            puts("Invalid register or register not accepted by the debugger...");
                        else
                        {
                            printf("[\x1B[01;93m%s\x1B[0m]> \x1B[31m0x%llx\x1B[0m => imm \x1B[32m 0x%lx\x1B[0m\n", registers[dst_op], reg_cpy[dst_op], val);
                            reg_cpy[dst_op] = val;
                            modify_regs(reg_cpy, &regs);
                            patch_regs(pid, &regs);
                        }
                    }
                    else if (*src == '$') // registrador....
                    {
                        dst++;
                        src++;
                        short dst_op = -1, src_op = -1;

                        // locate and patch the correct value

                        for (short i = 0; i < USER_REGS_STRUCT_NO; ++i)
                        {
                            if (dst_op != -1 && src_op != -1)
                                break;
                            if (strncmp(registers[i], dst, 3) == 0)
                                dst_op = i;
                            if (strncmp(registers[i], src, 3) == 0)
                                src_op = i;
                        }

                        if (dst_op == -1 || src_op == -1)
                            puts("Invalid register or register not accepted by the debugger...");
                        else
                        {
                            printf("[\x1B[01;93m%s\x1B[0m]> \x1B[31m0x%llx\x1B[0m => reg [\x1B[01;93m%s\x1B[0m]\x1B[32m 0x%llx\x1B[0m\n", registers[dst_op], reg_cpy[dst_op], registers[src_op], reg_cpy[src_op]);
                            reg_cpy[dst_op] = reg_cpy[src_op];
                            modify_regs(reg_cpy, &regs);
                            patch_regs(pid, &regs);
                        }
                    }
                    else
                    {
                        puts("\x1B[01;93mHint\x1B[0m: man set");
                        goto prompt_label;
                    }
                }
                else
                {
                    puts("\x1B[01;93mHint\x1B[0m: man set");
                    goto prompt_label;
                }
            }
            else if (strstr(buffer, "bp") != NULL)
            {
                char *tokens = strtok(buffer, " ");
                char *args[2];

                sep_tokens(tokens, args);

                char *breakpoint = args[1];

                if (*breakpoint == '*') // endereço
                {
                    breakpoint++;
                    long addr_bp = strtol(breakpoint, NULL, 16);

                    if (elf_type == 2)
                        addr_bp += base;

                    printf("Breakpoint on \x1B[01;91m0x%lx\x1B[0m\n", addr_bp);
                    long bp = set_breakpoint(pid, addr_bp);
                    store_breakpoint(breakpoints, bp, addr_bp);
                }
                else // símbolo
                {
                    long addr_bp = find_symbol_addr(symtab_size, breakpoint);

                    if (addr_bp == -1)
                    {
                        printf("[\x1B[01;93mWARNING\x1B[0m] Symbol %s not found...\n", breakpoint);
                        goto prompt_label;
                    }

                    if (elf_type == 2)
                        addr_bp += base;

                    printf("Breakpoint on \x1B[01;94m(%s)\x1B[0m => \x1B[01;91m0x%lx\x1B[0m\n", breakpoint, addr_bp);
                    long bp = set_breakpoint(pid, addr_bp);
                    store_breakpoint(breakpoints, bp, addr_bp);
                }
            }
            else
                puts("Command not found...");
            goto prompt_label;
        }
    }

end:
    printf("[\x1B[96m%ld\x1B[0m] End session....\n", (long)pid);
    return 0;
}

static inline void menu(void)
{
    puts("\x1B[01;95m");
    puts("░█████╗░░█████╗░░█████╗░██╗░░░░░  ██████╗░███████╗██████╗░██╗░░░██╗░██████╗░░██████╗░███████╗██████╗░");
    puts("██╔══██╗██╔══██╗██╔══██╗██║░░░░░  ██╔══██╗██╔════╝██╔══██╗██║░░░██║██╔════╝░██╔════╝░██╔════╝██╔══██╗");
    puts("██║░░╚═╝██║░░██║██║░░██║██║░░░░░  ██║░░██║█████╗░░██████╦╝██║░░░██║██║░░██╗░██║░░██╗░█████╗░░██████╔╝");
    puts("██║░░██╗██║░░██║██║░░██║██║░░░░░  ██║░░██║██╔══╝░░██╔══██╗██║░░░██║██║░░╚██╗██║░░╚██╗██╔══╝░░██╔══██╗");
    puts("╚█████╔╝╚█████╔╝╚█████╔╝███████╗  ██████╔╝███████╗██████╦╝╚██████╔╝╚██████╔╝╚██████╔╝███████╗██║░░██║");
    puts("░╚════╝░░╚════╝░░╚════╝░╚══════╝  ╚═════╝░╚══════╝╚═════╝░░╚═════╝░░╚═════╝░░╚═════╝░╚══════╝╚═╝░░╚═╝");
    putc(0xa, stdout);
    puts("██████╗░██╗░░░██╗  ██████╗░██╗███╗░░██╗░█████╗░██████╗░██╗░░░██╗");
    puts("██╔══██╗╚██╗░██╔╝  ██╔══██╗██║████╗░██║██╔══██╗██╔══██╗╚██╗░██╔╝");
    puts("██████╦╝░╚████╔╝░  ██████╦╝██║██╔██╗██║███████║██████╔╝░╚████╔╝░");
    puts("██╔══██╗░░╚██╔╝░░  ██╔══██╗██║██║╚████║██╔══██║██╔══██╗░░╚██╔╝░░");
    puts("██████╦╝░░░██║░░░  ██████╦╝██║██║░╚███║██║░░██║██║░░██║░░░██║░░░");
    puts("╚═════╝░░░░╚═╝░░░  ╚═════╝░╚═╝╚═╝░░╚══╝╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░");
    putc(0xa, stdout);
    puts("███╗░░██╗███████╗░██╗░░░░░░░██╗██████╗░██╗███████╗");
    puts("████╗░██║██╔════╝░██║░░██╗░░██║██╔══██╗██║██╔════╝");
    puts("██╔██╗██║█████╗░░░╚██╗████╗██╔╝██████╦╝██║█████╗░░");
    puts("██║╚████║██╔══╝░░░░████╔═████║░██╔══██╗██║██╔══╝░░");
    puts("██║░╚███║███████╗░░╚██╔╝░╚██╔╝░██████╦╝██║███████╗");
    puts("╚═╝░░╚══╝╚══════╝░░░╚═╝░░░╚═╝░░╚═════╝░╚═╝╚══════╝\x1B[0m");
    putc(0xa, stdout);

    printf("Hello \x1B[01;95m%s\x1B[0m !!!\nIf it is your first time, type \x1B[01;93mman\x1B[0m\n", username_from_uid(geteuid()));
}

static inline bool disable_aslr(void)
{
    unsigned long pers_value = PER_LINUX | ADDR_NO_RANDOMIZE;

    if (personality(pers_value) < 0)
    {
        if (personality(pers_value) < 0)
            return false;
    }
    return true;
}

char *username_from_uid(uid_t uid)
{
    struct passwd *pwd = getpwuid(uid);

    if (!pwd)
    {
        perror("getpwuid error: ");
        exit(EXIT_FAILURE);
    }

    return pwd->pw_name;
}

void *map_file(const char *path, long *length)
{
    FILE *f = fopen(path, "rb");
    int fd = 0;
    void *content;

    if (!f)
    {
        perror("fopen error: ");
        exit(EXIT_FAILURE);
    }

    fd = fileno(f);

    if (fseek(f, 0, SEEK_END) == -1)
    {
        fclose_wrapper(f);
        perror("fseek error: ");
        exit(EXIT_FAILURE);
    }

    *length = ftell(f);

    if (*length == -1)
    {
        fclose_wrapper(f);
        perror("ftell wrapper: ");
        exit(EXIT_FAILURE);
    }

    if (*length == 0)
    {
        fclose_wrapper(f);
        fprintf(stderr, "%s is empty or is a special file...\n", path);
        exit(EXIT_FAILURE);
    }

    rewind(f);

    content = mmap(NULL, *length, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (content == MAP_FAILED)
    {
        fclose_wrapper(f);
        perror("mmap error: ");
        exit(EXIT_FAILURE);
    }

    fclose_wrapper(f);
    return content;
}

void fclose_wrapper(FILE *file)
{
    if (fclose(file) == -1)
    {
        perror("fclose error: ");
        exit(EXIT_FAILURE);
    }
}

void munmap_wrapper(void *content, long size)
{
    if (munmap(content, size) == -1)
    {
        perror("munmap error: ");
        exit(EXIT_FAILURE);
    }
}

void free_sym(void)
{
    if (file_symbols != NULL)
        free(file_symbols);
}

short check_type(Elf64_Ehdr *elf_headers)
{
    switch (elf_headers->e_type)
    {
    case ET_EXEC:
    {
        puts("[\x1B[96mLOG\x1B[0m] Executable/static linked format...");
        return 1;
    }
    case ET_DYN:
    {
        puts("[\x1B[96mLOG\x1B[0m] Shared lib/Dynamic linked format...");
        return 2;
    }
    default:
    {
        puts("[\x1B[96mLOG\x1B[0m] Other format...");
        return 3;
    }
    }
}

bool hasSections(Elf64_Ehdr *elf_headers)
{
    if (elf_headers->e_shnum == 0 || elf_headers->e_shstrndx == 0 || elf_headers->e_shoff == 0)
        return false;
    return true;
}

struct breakpoint_t *extract_symbols(Elf64_Ehdr *elf_headers, char *content, long *sym_size)
{
    if (!hasSections(elf_headers))
    {
        puts("[\x1B[01;93mWARNING\x1B[0m] It doesn't have any sections...");
        return NULL;
    }

    char *strtab;
    Elf64_Sym *sym_tab;
    Elf64_Shdr *section_headers = (Elf64_Shdr *)((unsigned char *)elf_headers + elf_headers->e_shoff);
    struct breakpoint_t *symbols = NULL;

    for (int i = 1; i < elf_headers->e_shnum; ++i)
    {
        if (section_headers[i].sh_type == SHT_SYMTAB)
        {
            printf("[+] Found a symbol table at 0x%lx\n[+] End at 0x%lx\n[+] Size: 0x%lx\n", section_headers[i].sh_offset, section_headers[i].sh_offset + section_headers[i].sh_size, section_headers[i].sh_size);

            strtab = &content[section_headers[section_headers[i].sh_link].sh_offset];
            sym_tab = (Elf64_Sym *)(&content[section_headers[i].sh_offset]); // começo da secção
            *sym_size = (long)(section_headers[i].sh_size / sizeof(Elf64_Sym));
            symbols = calloc(*sym_size, sizeof(struct breakpoint_t));

            if (!symbols)
            {
                perror("calloc error: ");
                exit(EXIT_FAILURE);
            }

            for (long j = 0; j < (long)(section_headers[i].sh_size / sizeof(Elf64_Sym)); ++j, ++sym_tab)
            {
                symbols[j].symbol_name = strdup(&strtab[sym_tab->st_name]);
                symbols[j].breakpoint = 0;
                symbols[j].hit = 0;
                symbols[j].addr = sym_tab->st_value;
            }

            puts("[\x1B[96mLOG\x1B[0m] Symbol table parsed...");
            break;
        }
    }

    return symbols;
}

long find_symbol_addr(long symtab_size, const char *symbol)
{
    for (long i = 0; i < symtab_size; ++i)
        if (strcmp(file_symbols[i].symbol_name, symbol) == 0)
            return file_symbols[i].addr;
    return -1;
}

void display_simbols(long symtab_size)
{
    if (symtab_size == 0)
    {
        puts("\x1B[01;93mNo symbol table...\x1B[0m");
        return;
    }
    for (long i = 0; i < symtab_size; ++i)
        printf("Symbol (\x1B[96m%ld\x1B[0m) => \x1B[01;91m%s\x1B[0m at \x1B[32m0x%lx\x1B[0m\n", i, file_symbols[i].symbol_name, file_symbols[i].addr);
}

long get_base(pid_t pid)
{
    char path[PROCS_LENGTH] = {'\0'}, buffer[200] = {'\0'}, tmp_base[15] = {'\0'};
    unsigned long base = 0;
    int i = 0;
    size_t read = 0;

    sprintf(path, "/proc/%d/maps", pid);

    FILE *handler = fopen(path, "r");

    if (!handler)
    {
        free_sym();
        perror("fopen error: ");
        exit(EXIT_FAILURE);
    }

    read = fread(buffer, sizeof(char), 200, handler);

    if (read == (size_t)-1)
    {
        free_sym();
        fclose_wrapper(handler);
        perror("fread error: ");
        exit(EXIT_FAILURE);
    }

    for (char *tmp = buffer; *tmp != '\0' && *tmp != '-'; tmp++)
        tmp_base[i++] = *tmp;

    base = strtol(tmp_base, NULL, 16);
    fclose_wrapper(handler);
    return base;
}

void check_aslr(void)
{
    int persona = personality(CURRENT_PERSONA);

    if (persona == -1)
    {
        free_sym();
        perror("personality error: ");
        exit(EXIT_FAILURE);
    }

    if ((persona & ADDR_NO_RANDOMIZE) != 0)
    {
        puts("aslr is \x1B[31mdisabled\x1B[0m");
        return;
    }

    puts("aslr is \x1B[32menabled\x1B[0m");
}

void sep_tokens(char *tokens, char **args)
{
    int i = 0;

    while (tokens != NULL)
    {
        args[i] = tokens;
        i++;
        tokens = strtok(NULL, "\n");
    }
}

void patch_regs(pid_t pid, struct user_regs_struct *old_registers)
{
    struct user_regs_struct tmp_regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &tmp_regs) == -1)
    {
        free_sym();
        perror("ptrace GETREGS error: ");
        exit(EXIT_FAILURE);
    }

    tmp_regs = *old_registers;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &tmp_regs) == -1)
    {
        free_sym();
        perror("ptrace SETREGS error: ");
        exit(EXIT_FAILURE);
    }
}

long set_breakpoint(pid_t pid, long addr)
{
    long ptrace_res = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);

    if (ptrace_res == -1)
    {
        free_sym();
        perror("Ptrace PEEKTEXT error: ");
        exit(EXIT_FAILURE);
    }

    unsigned long long trap = (ptrace_res & ~0xff) | 0xcc;

    if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, trap) == -1)
    {
        free_sym();
        perror("Ptrace POKETEXT error: ");
        exit(EXIT_FAILURE);
    }

    return ptrace_res;
}

void store_breakpoint(struct breakpoint_t *breakpoint_list, long breakpoint, long addr)
{
    for (short i = 0; i < MAX_BREAKPOINTS; ++i)
    {
        if (i == (MAX_BREAKPOINTS - 1) && breakpoint_list[i].addr != 0 && breakpoint_list[i].breakpoint != 0)
        {
            puts("[\x1B[01;93mWarning\x1B[0m] The breakpoint list is full...");
            break;
        }

        if (breakpoint_list[i].addr == 0 && breakpoint_list[i].breakpoint == 0)
        {
            breakpoint_list[i].addr = addr;
            breakpoint_list[i].breakpoint = breakpoint;
            break;
        }
    }
}

bool resume_execution(pid_t pid, struct user_regs_struct *regs, struct breakpoint_t *breakpoins_list)
{
    struct breakpoint_t tmp;
    short which = 0;
    memset(&tmp, 0, sizeof(struct breakpoint_t));

    for (short i = 0; i < MAX_BREAKPOINTS; ++i)
    {
        if ((regs->rip - 1) == (unsigned long long)(breakpoins_list[i].addr))
        {
            tmp = breakpoins_list[i];
            breakpoins_list[i].hit++;
            which = i;
            break;
        }
    }

    if ((tmp.addr == 0 && tmp.breakpoint == 0) || tmp.hit > 0)
        return false;

    printf("[\x1B[96mBREAKPOINT\x1B[0m] Breakpoint \x1B[01;91m(%d)\x1B[0m hit at \x1B[01;90m0x%lx\x1B[0m\n", which, tmp.addr);

    if (ptrace(PTRACE_POKETEXT, pid, (void *)tmp.addr, tmp.breakpoint) == -1)
    {
        free_sym();
        perror("ptrace POKETEXT error: ");
        exit(EXIT_FAILURE);
    }

    regs->rip = tmp.addr;
    patch_regs(pid, regs);

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
    {
        free_sym();
        perror("ptrace CONT error: ");
        exit(EXIT_FAILURE);
    }

    return true;
}

void display_breakpoints(struct breakpoint_t *breakpoint_list)
{
    if (breakpoint_list[0].addr == 0 && breakpoint_list[0].breakpoint == 0)
    {
        puts("\x1B[01;93mThe breakpoint list is empty...\x1B[0m");
        return;
    }

    for (short i = 0; i < MAX_BREAKPOINTS; ++i)
    {
        if (breakpoint_list[i].addr == 0 && breakpoint_list[i].breakpoint == 0)
            break;
        printf("Breakpoint (\x1B[96m%d\x1B[0m) at \x1B[32m0x%lx\x1B[0m\n", i, breakpoint_list[i].addr);
    }
}

void copy_registers(unsigned long long *regs_cpy, struct user_regs_struct *original_regs)
{
    unsigned long long *ptr = &original_regs->r15; // first field of the struct
    for (int i = 0; i < USER_REGS_STRUCT_NO; ++i)
        regs_cpy[i] = *ptr++;
}

void modify_regs(unsigned long long *regs_cpy, struct user_regs_struct *new_regs)
{
    unsigned long long *ptr = &new_regs->r15;
    for (int i = 0; i < USER_REGS_STRUCT_NO; ++i)
        *ptr++ = regs_cpy[i];
}

void format_print(struct user_regs_struct *new_regs, struct user_regs_struct *saved, const char **registers)
{
    puts("\n\x1B[01;93mRegisters:\x1B[0m");
    printf("RAX: 0x%llx\nRBX: 0x%llx\nRCX: 0x%llx\nRDX: 0x%llx\nRSP: 0x%llx\nRBP: 0x%llx\nRSI: 0x%llx\nRDI: 0x%llx\nR8:  0x%llx\nR9:  0x%llx\nR10: 0x%llx\nR11: 0x%llx\nR12: 0x%llx\nR13: 0x%llx\nR14: 0x%llx\nR15: 0x%llx\n",
           new_regs->rax, new_regs->rbx, new_regs->rcx, new_regs->rdx, new_regs->rsp,
           new_regs->rbp, new_regs->rsi, new_regs->rdi, new_regs->r8,
           new_regs->r9, new_regs->r10, new_regs->r11, new_regs->r12, new_regs->r13,
           new_regs->r14, new_regs->r15);

    unsigned long long *ptr = &saved->r15;
    unsigned long long *ptr2 = &new_regs->r15;

    puts("\n\x1B[01;93mLast changes:\x1B[0m");

    for (int i = 0; i < USER_REGS_STRUCT_NO; ++i)
    {
        if (*ptr != *ptr2)
            printf("[\x1B[01;91m%s\x1B[0m] \x1B[31m0x%llx\x1B[0m => \x1B[32m0x%llx\x1B[0m\n", registers[i], *ptr, *ptr2);
        ptr++;
        ptr2++;
    }

    putc(0xa, stdout);
}