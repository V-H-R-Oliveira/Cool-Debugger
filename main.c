#include "debugger.h"

extern char **environ;

/*
    Implementar o dissasembler usando capstone -> ler section .text
    Implementar a stack
    Implementar checksec básico (NX, PIE, RERLO, Canary, Fortify)
    Paralelizar se possível com pthreads
*/

int main(int argc, char **argv)
{
    menu();

    if (argc < 2)
    {
        fprintf(stderr, "Usage %s <file> <cmdline args>\n", *argv);
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
    long length = 0, symtab_size = 0, base = 0;
    char *content = map_file(path, &length);
    pid_t pid = 0;
    struct user_regs_struct regs, saved = regs;
    int status = 0;
    struct breakpoint_t breakpoints[MAX_BREAKPOINTS];
    Elf64_Ehdr *elf_headers;
    short elf_type = 0;
    bool first_time = true;
    struct breakpoint_t *file_symbols;
    char previous[COMMAND_SIZE];
    
    if (*content != 0x7f && strncmp(&content[0], "ELF", 3) != 0)
    {
        fprintf(stderr, "%s isn't an elf...\n", path);
        munmap_wrapper(content, length);
        return 1;
    }

    elf_headers = (Elf64_Ehdr *)content;
    char **args = extract_cmdline_args(argc, argv);

    if (!args)
    {
        munmap_wrapper(content, length);
        return 1;
    }

    elf_type = check_type(elf_headers);
    file_symbols = extract_symbols(elf_headers, content, &symtab_size);
    munmap_wrapper(content, length);

    if (!disable_aslr())
        puts("Not able to disable ASLR :(");

    pid = fork();

    if (pid == -1)
    {
        free_wrapper(file_symbols);
        perror("fork error: ");
        return 1;
    }

    if (pid == 0) // child
    {
        if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) == -1)
        {
            free_wrapper(file_symbols);
            perror("ptrace TRACEME error: ");
            return 1;
        }

        if (execve(*args, args, environ) == -1)
        {
            free_wrapper(file_symbols);
            free_wrapper(args);
            perror("execve error: ");
            return 1;
        }

        free_wrapper(args);
        return 0;
    }

    free_wrapper(args);
    memset(&breakpoints, 0, sizeof(struct breakpoint_t) * MAX_BREAKPOINTS);
    printf("[\x1B[96m%ld\x1B[0m] Init session....\n", (long)pid);

    for (;;)
    {
        if (wait(&status) == -1)
        {
            free_wrapper(file_symbols);
            perror("wait error: ");
            return 1;
        }

        if (WIFEXITED(status))
        {
            free_wrapper(file_symbols);
            break;
        }

        if (elf_type == 2 && first_time)
        {
            base = get_base(file_symbols, pid);
            first_time = false;
        }

        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
        {
            free_wrapper(file_symbols);
            perror("ptrace GETREGS error: ");
            return 1;
        }

        format_print(&regs, &saved, registers);
        disassembly_view(pid, &regs, file_symbols);
        
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        {
            if (resume_execution(pid, &regs, breakpoints, file_symbols))
                goto prompt_label;
        }

        copy_registers(reg_cpy, &regs);
        saved = regs;

        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
        {
            free_wrapper(file_symbols);
            perror("ptrace SINGLESTEP error: ");
            return 1;
        }

    prompt_label:
        printf("[\x1B[96m0x%llx\x1B[0m]> ", regs.rip);
        fflush(NULL);

        if (!fgets(buffer, COMMAND_SIZE, stdin))
        {
            free_wrapper(file_symbols);
            perror("fgets error: ");
            return 1;
        }

        if (*buffer != '\n' && strncmp(previous, buffer, sizeof(buffer)) != 0)
            memmove(previous, buffer, sizeof(buffer));

    select_command:
        if ((strlen(buffer) - 1) == 1)
        {
            switch (*buffer)
            {
            case 's':
            {
                continue;
                break;
            }
            case 'c':
            {
                if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
                {
                    free_wrapper(file_symbols);
                    perror("ptrace CONT error: ");
                    return 1;
                }

                break;
            }
            case 'q':
            {
                free_wrapper(file_symbols);
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
                else if (strncmp(info, "cmd", 3) == 0) // cmd
                    puts("\x1B[96mDebugger commands:\x1B[0m\nc -> continue\ns -> single step\nq -> quit");
                else if (strncmp(info, "check", 5) == 0) // check
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
                    check_aslr(file_symbols);
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
                    display_simbols(symtab_size, file_symbols);
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
                            patch_regs(pid, &regs, file_symbols);
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
                            patch_regs(pid, &regs, file_symbols);
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
                    long bp = set_breakpoint(pid, addr_bp, file_symbols);
                    store_breakpoint(breakpoints, bp, addr_bp);
                }
                else // símbolo
                {
                    long addr_bp = find_symbol_addr(file_symbols, symtab_size, breakpoint);

                    if (addr_bp == -1)
                    {
                        printf("[\x1B[01;93mWARNING\x1B[0m] Symbol %s not found...\n", breakpoint);
                        goto prompt_label;
                    }

                    if (elf_type == 2)
                        addr_bp += base;

                    printf("Breakpoint on \x1B[01;94m(%s)\x1B[0m => \x1B[01;91m0x%lx\x1B[0m\n", breakpoint, addr_bp);
                    long bp = set_breakpoint(pid, addr_bp, file_symbols);
                    store_breakpoint(breakpoints, bp, addr_bp);
                }
            }
            else
            {
                if (*buffer == '\n' && *previous != '\0')
                {
                    printf("[\x1B[01;93mINFO\x1B[0m] Executing the previous instruction: %s\n", previous);
                    strncpy(buffer, previous, strlen(previous));
                    goto select_command;
                }

                puts("\x1B[01;93mHint\x1B[0m: type man");
            }
            goto prompt_label;
        }
    }

end:
    printf("[\x1B[96m%ld\x1B[0m] End session....\n", (long)pid);
    return 0;
}
