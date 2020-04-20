#include "debugger.h"

extern char **environ;

int main(int argc, char **argv)
{
    menu();

    if (argc < 2)
    {
        fprintf(stderr, "Usage %s <file> <cmdline args>\n", *argv);
        return 1;
    }

    char buffer[COMMAND_SIZE] = {'\0'}, previous[COMMAND_SIZE] = {'\0'};
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
    const struct eflags_t flags[] = {
        {"CARRY", 0x1},
        {"PARITY", 0x4},
        {"ADJUST", 0x10},
        {"ZERO", 0x40},
        {"SIGN", 0x80},
        {"TRAP", 0x100},
        {"INTERRUPT", 0x200},
        {"DIRECTION", 0x400},
        {"OVERFLOW", 0x800},
    };
    const char *path = argv[1];
    long length = 0, symtab_size = 0, base = 0;
    char *content = map_file(path, &length);
    pid_t pid = 0;
    struct user_regs_struct regs, saved;
    int status = 0;
    struct breakpoint_t breakpoints[MAX_BREAKPOINTS], *file_symbols;
    Elf64_Ehdr *elf_headers;
    short elf_type = 0;
    bool first_time = true;
    size_t previous_length = 0;
    char **args;

    if (!isElf(content))
    {
        fprintf(stderr, "%s isn't an elf...\n", path);
        munmap_wrapper(content, length);
        return 1;
    }

    elf_headers = (Elf64_Ehdr *)content;

    if (!is_x86_64(elf_headers))
    {
        fprintf(stderr, "%s isn't supported...\nCurrent arch support: x86_64\n", path);
        munmap_wrapper(content, length);
        return 1;
    }

    args = extract_cmdline_args(argc, argv);

    if (!args)
    {
        munmap_wrapper(content, length);
        return 1;
    }

    elf_type = check_type(elf_headers);
    file_symbols = extract_symbols(elf_headers, content, &symtab_size, args);

    munmap_wrapper(content, length);

    if (!disable_aslr())
        puts("Not able to disable ASLR :(");

    pid = fork();

    if (pid == -1)
    {
        free_cmdargs(args);
        free_sym(file_symbols, symtab_size);
        perror("fork error: ");
        return 1;
    }

    if (pid == 0) // child
    {
        if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) == -1)
        {
            free_cmdargs(args);
            free_sym(file_symbols, symtab_size);
            perror("ptrace TRACEME error: ");
            return 1;
        }

        if (execve(*args, args, environ) == -1)
        {
            free_cmdargs(args);
            free_sym(file_symbols, symtab_size);
            perror("execve error: ");
            return 1;
        }

        free_cmdargs(args);
        return 0;
    }

    free_cmdargs(args);
    memset(&breakpoints, 0, sizeof(struct breakpoint_t) * MAX_BREAKPOINTS);
    memset(&saved, 0, sizeof(struct user_regs_struct));
    printf("[\x1B[96m%ld\x1B[0m] Init session....\n", (long)pid);

    for (;;)
    {
        if (wait(&status) == -1)
        {
            free_sym(file_symbols, symtab_size);
            perror("wait error: ");
            return 1;
        }

        if (first_time)
        {
            if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL) == -1)
            {
                free_sym(file_symbols, symtab_size);
                perror("ptrace SETOPTIONS error: ");
                return 1;
            }
        }

        if (WIFEXITED(status))
        {
            free_sym(file_symbols, symtab_size);
            break;
        }

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
        {
            free_sym(file_symbols, symtab_size);
            break;
        }

        if (elf_type == 2 && first_time)
        {
            base = get_base(pid, file_symbols, symtab_size);
            first_time = false;
        }

        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
        {
            free_sym(file_symbols, symtab_size);
            perror("ptrace GETREGS error: ");
            return 1;
        }

        format_print(&regs, &saved, registers, flags);

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
            resume_execution(pid, &regs, breakpoints, file_symbols, symtab_size);

        copy_registers(reg_cpy, &regs);
        saved = regs;
        disassembly_view(pid, &regs, file_symbols, symtab_size);

    prompt_label:
        printf("[\x1B[96m0x%llx\x1B[0m]> ", regs.rip);

        if (!fgets(buffer, COMMAND_SIZE, stdin))
        {
            free_sym(file_symbols, symtab_size);
            perror("fgets error: ");
            return 1;
        }

        if (*buffer != '\n' && previous != NULL && strncmp(previous, buffer, sizeof(buffer)) != 0)
        {
            previous_length = strlen(buffer);
            memmove(previous, buffer, sizeof(buffer));
        }

    select_command:
        if ((strlen(buffer) - 1) == 1)
        {
            switch (*buffer)
            {
            case 's':
            {
                if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
                {
                    free_sym(file_symbols, symtab_size);
                    perror("ptrace SINGLESTEP error: ");
                    return 1;
                }
                continue;
            }
            case 'c':
            {
                if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
                {
                    free_sym(file_symbols, symtab_size);
                    perror("ptrace CONT error: ");
                    return 1;
                }

                break;
            }
            case 'q':
            {
                if (ptrace(PTRACE_KILL, pid, NULL, NULL) == -1)
                {
                    free_sym(file_symbols, symtab_size);
                    perror("ptrace KILL error: ");
                    return 1;
                }

                continue;
            }
            default:
                puts("\x1B[01;93mHint\x1B[0m: man cmd");
                break;
            }
        }
        else
        {
            if (strstr(buffer, "man") != NULL)
                display_man(buffer);
            else if (strstr(buffer, "check") != NULL)
                check_feature(buffer, file_symbols, symtab_size);
            else if (strstr(buffer, "info") != NULL)
                display_process_info(buffer, breakpoints, file_symbols, symtab_size);
            else if (strstr(buffer, "inspect") != NULL)
                inspect_memory(pid, buffer, file_symbols, symtab_size, registers, elf_type, base);
            else if (strstr(buffer, "set") != NULL)
                set_command(pid, buffer, registers, reg_cpy, &regs, file_symbols, symtab_size);
            else if (strstr(buffer, "bp") != NULL)
                bp_command(pid, buffer, breakpoints, elf_type, base, file_symbols, symtab_size);
            else
            {
                if (*buffer == '\n' && *previous != '\0')
                {
                    printf("[\x1B[01;93mINFO\x1B[0m] Executing the previous instruction: %s\n", previous);
                    strncpy(buffer, previous, previous_length);
                    goto select_command;
                }

                puts("\x1B[01;93mHint\x1B[0m: type man");
            }

            goto prompt_label;
        }
    }

    printf("[\x1B[96m%ld\x1B[0m] End session....\n", (long)pid);
    return 0;
}
