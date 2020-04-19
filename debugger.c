#include "debugger.h"

void menu(void)
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

bool disable_aslr(void)
{
    unsigned long pers_value = PER_LINUX | ADDR_NO_RANDOMIZE;

    if (personality(pers_value) < 0)
    {
        if (personality(pers_value) < 0)
            return false;
    }
    return true;
}

char **extract_cmdline_args(int argc, char **argv)
{
    char **args = calloc(argc, sizeof(char *));

    if (!args)
    {
        perror("calloc error: ");
        return NULL;
    }

    args[0] = strdup(argv[1]);

    if (!(*args))
    {
        free(args);
        perror("strdup error: ");
        return NULL;
    }

    for (int i = 2; i < argc; ++i)
    {
        args[i - 1] = strdup(argv[i]);

        if (!(args[i - 1]))
        {
            free(args);
            perror("strdup error: ");
            return NULL;
        }
    }

    args[argc - 1] = NULL;
    return args;
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

    content = mmap(NULL, *length, PROT_READ, MAP_PRIVATE, fd, 0);

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

void free_sym(struct breakpoint_t *file_symbols, long file_symbols_size)
{
    if (file_symbols != NULL)
    {
        for (long i = 0; i < file_symbols_size; ++i)
            free(file_symbols[i].symbol_name);
        free(file_symbols);
    }
}

void free_cmdargs(char **cmdargs)
{
    if (cmdargs != NULL)
    {
        for (char **tmp = cmdargs; *tmp != NULL; ++tmp)
            free(*tmp);
        free(cmdargs);
    }
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

struct breakpoint_t *extract_symbols(Elf64_Ehdr *elf_headers, char *content, long *sym_size, char **cmdargs)
{
    if (!hasSections(elf_headers))
    {
        puts("[\x1B[01;93mWARNING\x1B[0m] It doesn't have any sections...");
        return NULL;
    }

    char *strtab;
    Elf64_Sym *sym_tab;
    Elf64_Shdr *section_headers = (Elf64_Shdr *)((unsigned char *)elf_headers + elf_headers->e_shoff);
    struct breakpoint_t *symbols;
    const long pagesize = sysconf(_SC_PAGE_SIZE);

    if (pagesize == -1)
    {
        free_cmdargs(cmdargs);
        perror("sysconf error: ");
        exit(EXIT_FAILURE);
    }

    for (int i = 1; i < elf_headers->e_shnum; ++i)
    {
        if (section_headers[i].sh_type == SHT_SYMTAB)
        {
            printf("[+] Found a symbol table at 0x%lx\n[+] End at 0x%lx\n[+] Size: 0x%lx\n", section_headers[i].sh_offset, section_headers[i].sh_offset + section_headers[i].sh_size, section_headers[i].sh_size);

            strtab = &content[section_headers[section_headers[i].sh_link].sh_offset];
            sym_tab = (Elf64_Sym *)(&content[section_headers[i].sh_offset]); // começo da secção
            *sym_size = (long)(section_headers[i].sh_size / sizeof(Elf64_Sym));

            if (posix_memalign((void **)&symbols, pagesize, *sym_size * sizeof(struct breakpoint_t)) != 0)
            {
                free_cmdargs(cmdargs);
                perror("posix memalign error: ");
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
            return symbols;
        }
    }

    puts("[\x1B[01;93mWARNING\x1B[0m] It doesn't have symbols, maybe it is stripped...");
    return NULL;
}

long find_symbol_addr(struct breakpoint_t *file_symbols, long symtab_size, const char *symbol)
{
    for (long i = 0; i < symtab_size; ++i)
        if (strcmp(file_symbols[i].symbol_name, symbol) == 0)
            return file_symbols[i].addr;
    return -1;
}

void display_simbols(long symtab_size, struct breakpoint_t *file_symbols)
{
    if (symtab_size == 0)
    {
        puts("\x1B[01;93mNo symbol table...\x1B[0m");
        return;
    }

    for (long i = 0; i < symtab_size; ++i)
        printf("Symbol (\x1B[96m%ld\x1B[0m) => \x1B[01;91m%s\x1B[0m at \x1B[32m0x%lx\x1B[0m\n", i, file_symbols[i].symbol_name, file_symbols[i].addr);
}

long get_base(pid_t pid, struct breakpoint_t *file_symbols, long file_symbols_size)
{
    char path[PROCS_LENGTH] = {'\0'}, buffer[200] = {'\0'}, tmp_base[15] = {'\0'};
    unsigned long base = 0;
    int i = 0;
    size_t read = 0;
    FILE *handler;

    sprintf(path, "/proc/%d/maps", pid);

    handler = fopen(path, "r");

    if (!handler)
    {
        free_sym(file_symbols, file_symbols_size);
        perror("fopen error: ");
        exit(EXIT_FAILURE);
    }

    read = fread(buffer, sizeof(char), 200, handler);

    if (read == (size_t)-1)
    {
        free_sym(file_symbols, file_symbols_size);
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

void check_aslr(struct breakpoint_t *file_symbols, long file_symbols_size)
{
    int persona = personality(CURRENT_PERSONA);

    if (persona == -1)
    {
        free_sym(file_symbols, file_symbols_size);
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
    short i = 0;

    while (tokens != NULL)
    {
        args[i] = tokens;
        i++;
        tokens = strtok(NULL, "\n");
    }
}

void patch_regs(pid_t pid, struct user_regs_struct *old_registers, struct breakpoint_t *file_symbols, long file_symbols_size)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, old_registers) == -1)
    {
        free_sym(file_symbols, file_symbols_size);
        perror("ptrace SETREGS error: ");
        exit(EXIT_FAILURE);
    }
}

long set_breakpoint(pid_t pid, long addr, struct breakpoint_t *file_symbols, long file_symbols_size)
{
    long ptrace_res = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
    unsigned long long trap = 0;

    if (ptrace_res == -1)
    {
        free_sym(file_symbols, file_symbols_size);
        perror("Ptrace PEEKTEXT error: ");
        exit(EXIT_FAILURE);
    }

    trap = (ptrace_res & ~0xff) | 0xcc;

    if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, trap) == -1)
    {
        free_sym(file_symbols, file_symbols_size);
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

void resume_execution(pid_t pid, struct user_regs_struct *regs, struct breakpoint_t *breakpoins_list, struct breakpoint_t *file_symbols, long file_symbols_size)
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
        return;

    printf("[\x1B[96mBREAKPOINT\x1B[0m] Breakpoint \x1B[01;91m(%d)\x1B[0m hit at \x1B[01;90m0x%lx\x1B[0m\n\n", which, tmp.addr);

    if (ptrace(PTRACE_POKETEXT, pid, (void *)tmp.addr, tmp.breakpoint) == -1)
    {
        free_sym(file_symbols, file_symbols_size);
        perror("ptrace POKETEXT error: ");
        exit(EXIT_FAILURE);
    }

    regs->rip = tmp.addr;
    patch_regs(pid, regs, file_symbols, file_symbols_size);
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
    printf(
        "\n"
        "|RAX: 0x%012llx | EAX: 0x%08x  | AX:  0x%04x  | AL: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|RBX: 0x%012llx | EBX: 0x%08x  | BX:  0x%04x  | BL: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|RCX: 0x%012llx | ECX: 0x%08x  | CX:  0x%04x  | CL: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|RDX: 0x%012llx | EDX: 0x%08x  | DX:  0x%04x  | DL: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|RSP: 0x%012llx | ESP: 0x%08x  | SP:  0x%04x  | SPL: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|RBP: 0x%012llx | EBP: 0x%08x  | BP:  0x%04x  | BPL: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|RSI: 0x%012llx | ESI: 0x%08x  | SI:   0x%04x | SIL: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|RDI: 0x%012llx | EDI: 0x%08x  | DI:   0x%04x | DIL: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|R8:  0x%012llx | R8D: 0x%08x  | R8W:  0x%04x | R8B: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|R9:  0x%012llx | R9D: 0x%08x  | R9W:  0x%04x | R9B: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|R10: 0x%012llx | R10D: 0x%08x | R10W: 0x%04x | R10B: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|R11: 0x%012llx | R11D: 0x%08x | R11W: 0x%04x | R11B: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|R12: 0x%012llx | R12D: 0x%08x | R12W: 0x%04x | R12B: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|R13: 0x%012llx | R13D: 0x%08x | R13W: 0x%04x | R13B: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|R14: 0x%012llx | R14D: 0x%08x | R14W: 0x%04x | R14B: 0x%02x\n"
        "-----------------------------------------------------------------\n"
        "|R15: 0x%012llx | R15D: 0x%08x | R15W: 0x%04x | R15B: 0x%02x\n",
        new_regs->rax, (uint32_t)new_regs->rax, (uint16_t)new_regs->rax, (uint8_t)new_regs->rax,
        new_regs->rbx, (uint32_t)new_regs->rbx, (uint16_t)new_regs->rbx, (uint8_t)new_regs->rbx,
        new_regs->rcx, (uint32_t)new_regs->rcx, (uint16_t)new_regs->rcx, (uint8_t)new_regs->rcx,
        new_regs->rdx, (uint32_t)new_regs->rdx, (uint16_t)new_regs->rdx, (uint8_t)new_regs->rdx,
        new_regs->rsp, (uint32_t)new_regs->rsp, (uint16_t)new_regs->rsp, (uint8_t)new_regs->rsp,
        new_regs->rbp, (uint32_t)new_regs->rbp, (uint16_t)new_regs->rbp, (uint8_t)new_regs->rbp,
        new_regs->rsi, (uint32_t)new_regs->rsi, (uint16_t)new_regs->rsi, (uint8_t)new_regs->rsi,
        new_regs->rdi, (uint32_t)new_regs->rdi, (uint16_t)new_regs->rdi, (uint8_t)new_regs->rdi,
        new_regs->r8, (uint32_t)new_regs->r8, (uint16_t)new_regs->r8, (uint8_t)new_regs->r8,
        new_regs->r9, (uint32_t)new_regs->r9, (uint16_t)new_regs->r9, (uint8_t)new_regs->r9,
        new_regs->r10, (uint32_t)new_regs->r10, (uint16_t)new_regs->r10, (uint8_t)new_regs->r10,
        new_regs->r11, (uint32_t)new_regs->r11, (uint16_t)new_regs->r11, (uint8_t)new_regs->r11,
        new_regs->r12, (uint32_t)new_regs->r12, (uint16_t)new_regs->r12, (uint8_t)new_regs->r12,
        new_regs->r13, (uint32_t)new_regs->r13, (uint16_t)new_regs->r13, (uint8_t)new_regs->r13,
        new_regs->r14, (uint32_t)new_regs->r14, (uint16_t)new_regs->r14, (uint8_t)new_regs->r14,
        new_regs->r15, (uint32_t)new_regs->r15, (uint16_t)new_regs->r15, (uint8_t)new_regs->r15);

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

void extract_bytes(uint8_t *bytes, long data)
{
    bytes[0] = (uint8_t)data;
    bytes[1] = (uint8_t)(data >> 8);
    bytes[2] = (uint8_t)(data >> 16);
    bytes[3] = (uint8_t)(data >> 24);
    bytes[4] = (uint8_t)(data >> 32);
    data >>= 32;
    bytes[5] = (uint8_t)(data >> 8);
    bytes[6] = (uint8_t)(data >> 16);
    bytes[7] = (uint8_t)(data >> 24);
}

void extract_gdb_words(uint32_t *gdb_words, long gdb_word, long gdb_word2)
{
    gdb_words[0] = (uint32_t)gdb_word;
    gdb_words[1] = (uint32_t)(gdb_word >> 32);
    gdb_words[2] = (uint32_t)gdb_word2;
    gdb_words[3] = (uint32_t)(gdb_word2 >> 32);
}

void disassembly_view(pid_t pid, struct user_regs_struct *regs, struct breakpoint_t *file_symbols, long file_symbols_size)
{
    csh handle;
    cs_insn *insn;
    size_t count = 0;
    uint8_t bytes[OPCODES] = {'\0'};
    long opcodes = 0;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        free_sym(file_symbols, file_symbols_size);
        return;
    }

    opcodes = ptrace(PTRACE_PEEKTEXT, pid, regs->rip, NULL);

    if (opcodes == -1)
    {
        free_sym(file_symbols, file_symbols_size);
        perror("ptrace PEEKTEXT error: ");
        exit(EXIT_FAILURE);
    }

    extract_bytes(bytes, opcodes);
    count = cs_disasm(handle, bytes, sizeof(bytes), regs->rip, 0, &insn);

    if (count > 0)
    {
        puts("\x1B[01;93mDisassembly view:\x1B[0m\n");

        for (size_t j = 0; j < count; ++j)
            printf("\x1B[96m0x%" PRIx64 ":\x1B[0m\t%s\t\t%s\n", insn[j].address,
                   insn[j].mnemonic, insn[j].op_str);

        putc(0xa, stdout);
        cs_free(insn, count);
    }
    else
        puts("\x1B[31mERROR\x1B[0m: Failed to disassemble given code!");

    cs_close(&handle);
}

void peek_bytes_reg(pid_t pid, long amount, long regs_rt, struct breakpoint_t *file_symbols, long file_symbols_size)
{
    int far_offset = (int)(amount / sizeof(long));
    long data = 0, count = 0;
    uint8_t bytes[OPCODES];
    putc(0xa, stdout);

    for (int i = 0; i <= far_offset; ++i)
    {
        data = ptrace(PTRACE_PEEKDATA, pid, regs_rt + (sizeof(long) * i), NULL);

        if (data == -1)
        {
            free_sym(file_symbols, file_symbols_size);
            perror("Ptrace PEEKDATA error: ");
            exit(EXIT_FAILURE);
        }

        extract_bytes(bytes, data);
        printf("[\x1B[01;91m0x%lx\x1B[0m]> ", regs_rt + (sizeof(long) * i));

        for (short i = 0; i < OPCODES; ++i)
        {
            if (count < amount)
            {
                if (i != (OPCODES - 1))
                {
                    printf("\x1B[32m0x%02x ", bytes[i]);
                    count++;
                    continue;
                }

                printf("0x%02x\x1B[0m\n", bytes[i]);
                count++;
            }
        }
    }

    putc(0xa, stdout);
    putc(0xa, stdout);
}

void peek_words_reg(pid_t pid, long amount, long regs_rt, struct breakpoint_t *file_symbols, long file_symbols_size)
{
    int far_offset = (int)(amount / sizeof(uint16_t)) + 1;
    long word = 0, word2 = 0, count = 0;
    uint32_t gdb_words[4]; // gdb doesn't respect words (16 bits), it shows a dword.

    if (amount % 4 == 0) // for printing stuff
        far_offset--;

    putc(0xa, stdout);

    for (int i = 0; i < far_offset; i += 2)
    {
        word = ptrace(PTRACE_PEEKDATA, pid, regs_rt + (sizeof(long) * i), NULL);

        if (word == -1)
        {
            free_sym(file_symbols, file_symbols_size);
            perror("Ptrace PEEKDATA error: ");
            exit(EXIT_FAILURE);
        }

        word2 = ptrace(PTRACE_PEEKDATA, pid, regs_rt + (sizeof(long) * (i + 1)), NULL);

        if (word2 == -1)
        {
            free_sym(file_symbols, file_symbols_size);
            perror("Ptrace PEEKDATA error: ");
            exit(EXIT_FAILURE);
        }

        extract_gdb_words(gdb_words, word, word2);
        printf("[\x1B[01;91m0x%lx\x1B[0m]> ", regs_rt + (sizeof(long) * i));

        for (short i = 0; i < 4; ++i)
        {
            if (count < amount)
            {
                if (i != 3)
                {
                    printf("\x1B[32m0x%04x ", gdb_words[i]);
                    count++;
                    continue;
                }

                printf("0x%04x\x1B[0m\n", gdb_words[i]);
                count++;
            }
        }
    }

    putc(0xa, stdout);

    if (amount % 4 != 0) // for printing stuff
        putc(0xa, stdout);
}