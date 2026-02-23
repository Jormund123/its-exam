# Phase 2: Applied Offensive Security (~30 pts — HIGH)

**Slides covered:** 02 (Applied Binary Exploitation), 06 (Malware Analysis), 07 (Fuzzing)
**Exam evidence:** All 3 topics appeared on W2023/24 (10 pts each = 30 pts total). Fuzzing also appeared on W2022/23 with nearly identical questions. Binary exploitation is the hardest pen-and-paper question.

---

## Topic 1: Applied Binary Exploitation (Slide 02)

> **ASKED ON EXAM** — W2023/24, Exercise 4 (10pts): *"Prepare the payload to overflow variable x to exploit a program with a ROP chain which calls execve('/bin/sh', NULL, NULL). Write it into the stack diagram with brief explanations."*

### 1.1 x86-64 Assembler Basics

The 64-bit general-purpose registers are `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rdi`, `rsi`, and `r8` through `r15`. The special-purpose register `rip` holds the instruction pointer, which points to the next instruction to execute. The register `rsp` always points to the top of the stack, and `rbp` is conventionally used as the base pointer for the current stack frame.

The essential assembly instructions are:

- `mov dst, src` copies data from the source to the destination.
- `push val` decrements `rsp` by 8 and writes the value onto the stack.
- `pop reg` reads the value at `rsp` into the register and increments `rsp` by 8.
- `add dst, src` adds the source value onto the destination.
- `sub dst, src` subtracts the source from the destination.
- `xor dst, src` performs a bitwise XOR of the two operands and stores the result in the destination.
- `call addr` pushes the address of the next instruction onto the stack and jumps to `addr`.
- `ret` pops the top of the stack into `rip`, effectively returning to the caller.
- `cmp a, b` subtracts `b` from `a` and sets CPU flags (without storing the result).
- `je addr` jumps to `addr` if the zero flag is set (i.e., the previous comparison found equality).
- `syscall` asks the operating system to perform a kernel-level operation.

Intel syntax is used throughout the lecture: `mov rbp, rsp` means "copy rsp into rbp" (destination comes first).

### 1.2 Static and Dynamic Analysis

**Static analysis** examines the binary without executing it. The tool `objdump -d -Mintel binary` disassembles the binary into Intel-syntax assembly. This lets you see the program's code, function boundaries, and string references.

**Dynamic analysis** runs the binary under a debugger like GDB (the GNU Debugger). GDB allows you to set breakpoints, step through instructions one at a time, inspect register and memory contents, and modify values at runtime. Key GDB commands include:

| Command | Shortcut | Effect |
|---------|----------|--------|
| `run` | `r` | Start the program |
| `break addr` | `b addr` | Set a breakpoint |
| `nexti` | `ni` | Step over one instruction |
| `stepi` | `si` | Step into a function call |
| `continue` | `c` | Resume execution |
| `disassemble` | — | Show assembly of current function |
| `info registers` | — | Print all register values |
| `set $reg = value` | — | Change a register's value |
| `x/nfu addr` | — | Examine memory (n=count, f=format, u=unit) |

### 1.3 Stack Frames

When a function is called, the CPU automatically pushes the return address (the address of the instruction after the `call`) onto the stack. The function prologue then executes:

```
push rbp          ; save the caller's frame pointer
mov rbp, rsp      ; set the new frame pointer to the current stack top
sub rsp, N        ; allocate N bytes for local variables
```

This creates the following stack layout (from high addresses to low):

```
[return address]    ← placed here by the call instruction
[saved rbp]         ← saved by push rbp
[local variables]   ← allocated by sub rsp, N
         ↑ rsp points here (top of stack, lowest address)
```

When the function returns, the epilogue reverses this:

```
mov rsp, rbp      ; deallocate local variables
pop rbp           ; restore the caller's frame pointer
ret               ; pop return address into rip and jump there
```

### 1.4 System V Calling Convention (64-bit)

On 64-bit Linux, the System V ABI defines how function arguments are passed:

| Argument | Register |
|----------|----------|
| 1st | `rdi` |
| 2nd | `rsi` |
| 3rd | `rdx` |
| 4th | `rcx` |
| 5th | `r8` |
| 6th | `r9` |
| 7th+ | on the stack |

The return value is stored in `rax`. The caller is responsible for cleaning up any stack-passed arguments after the call returns.

### 1.5 Buffer Overflows

A buffer overflow occurs when a program writes more data into a buffer than it was allocated to hold. The excess data overwrites adjacent memory on the stack. Dangerous C functions that do not perform bounds checking include:

- `gets(buffer)` reads from stdin until a newline, with no size limit.
- `strcpy(dst, src)` copies a string without checking whether the destination is large enough.
- `memcpy(dst, src, n)` copies exactly `n` bytes, which can exceed the buffer size if `n` is too large.

Because local variables, the saved `rbp`, and the return address are all stored contiguously on the stack, an overflow can overwrite the return address. By carefully crafting the overflow data, an attacker can redirect execution to any address of their choosing.

**Example:** If a buffer of 32 bytes is followed by 8 bytes of saved `rbp` and then the 8-byte return address, the attacker needs to write 32 bytes of padding (to fill the buffer), 8 bytes of junk (to overwrite `rbp`), and then the desired 8-byte target address (to hijack the return).

### 1.6 Mitigations

**DEP (Data Execution Prevention)** marks memory pages as either writable or executable, but never both. The stack is writable but not executable, so even if an attacker places shellcode on the stack, the CPU will refuse to execute it. DEP is also called NX (No-Execute) or W^X (Write XOR Execute).

**Stack Canary** is a random value that the compiler places between the local variables and the saved frame pointer. Before the function returns, it checks whether the canary still has its original value. If the canary has been modified by an overflow, the program immediately aborts. This prevents simple buffer overflow exploits but can be bypassed if the attacker can leak the canary value.

**ASLR (Address Space Layout Randomization)** loads the program binary, shared libraries, stack, and heap at randomized addresses each time the program starts. This means an attacker cannot predict where functions, gadgets, or strings are located in memory. ASLR can be bypassed by leaking an address from the program (e.g., via a format string vulnerability or an information disclosure) and computing all other addresses relative to it.

### 1.7 Return-Oriented Programming (ROP)

ROP is the standard technique for exploiting buffer overflows when DEP is active. Instead of injecting new executable code, ROP reuses short instruction sequences already present in the program or its libraries. These sequences are called **gadgets**, and each one ends with a `ret` instruction.

When a function returns, it pops the top of the stack into `rip`. If the attacker has overwritten the stack, execution jumps to the first gadget. That gadget executes its instructions and then its own `ret` pops the next address from the stack, jumping to the second gadget, and so on. This chain of gadgets can perform arbitrary computations.

Gadgets are found using tools like `ROPgadget --binary /path/to/library`.

### 1.8 ROP Strategy 1: ret2libc

The simplest ROP attack calls `system("/bin/sh")` from libc. The `system()` function takes a single argument (a command string) in `rdi` and executes it as a shell command.

The required components are:
1. A `pop rdi; ret` gadget (to load the argument into `rdi`)
2. The address of the string `"/bin/sh"` in libc
3. The address of the `system()` function in libc

The stack layout after the overflow is:

```
[padding to fill buffer + saved rbp]
[address of: pop rdi; ret]      ← return address points here
[address of: "/bin/sh"]          ← popped into rdi
[address of: system()]           ← ret jumps here, calling system("/bin/sh")
```

### 1.9 ROP Strategy 2: sys_execve via Syscall

This approach makes a direct `execve` syscall without calling any libc function. The `execve` syscall number is **0x3b** (59 in decimal) on x86-64 Linux. The registers must be set as follows:

| Register | Value | Purpose |
|----------|-------|---------|
| `rax` | `0x3b` | syscall number for execve |
| `rdi` | pointer to `"/bin/sh\0"` | filename to execute |
| `rsi` | `0` (NULL) | argv array |
| `rdx` | `0` (NULL) | envp array |

The ROP chain uses gadgets to load each register, then ends with a `syscall` gadget:

```
[pop rax; ret]       → sets rax = 0x3b
[0x000000000000003b]
[pop rsi; ret]       → sets rsi = 0
[0x0000000000000000]
[pop rdx; ret]       → sets rdx = 0 (some gadgets also pop rbx)
[0x0000000000000000]
[pop rdi; ret]       → sets rdi = address of "/bin/sh\0"
[addr of "/bin/sh"]
[syscall]            → triggers execve("/bin/sh", NULL, NULL)
```

### 1.10 ROP Strategy 3: mprotect + Shellcode

If your ROP chain length is limited or gadgets are scarce, you can use `mprotect()` to make a memory region both writable and executable, then jump into shellcode that is already in memory (e.g., in the buffer itself). The `mprotect` syscall takes three arguments: the page-aligned address, the length, and the protection flags (`PROT_READ | PROT_WRITE | PROT_EXEC = 7`).

### 1.11 Working Around ASLR

When ASLR is active, addresses change with every program run. To bypass it, the attacker needs a way to leak a known address at runtime. A common approach is to find a code path that prints or returns a function pointer or library address. Once you know one address inside a library, you can compute the base address by subtracting the known offset, and then all other offsets can be calculated.

### 1.12 Little-Endian Byte Ordering

The x86-64 architecture uses little-endian byte ordering, which means the least significant byte is stored at the lowest memory address. When writing an address like `0x7fff40000042` into the payload, you must reverse the byte order: `42 00 00 40 ff 7f 00 00`. Getting the byte order wrong is one of the most common mistakes in ROP chain construction.

### 1.13 Exam Strategy: Filling the Stack Diagram

When the exam gives you a stack diagram to fill:

1. **Identify the variable, saved rbp, and return address slots** from the given stack layout.
2. **Compute absolute addresses** for each gadget by adding the offset to the library base address.
3. **Fill the variable slot** with padding (any value, or keep the original).
4. **Fill the saved rbp slot** with padding (any 8 bytes — it does not matter for the exploit).
5. **Starting at the return address**, write the ROP chain: each gadget address followed by its argument value(s).
6. **Write all addresses in little-endian** format.
7. **Add brief explanations** for each row (e.g., "pop rdi; ret gadget", "pointer to /bin/sh", "syscall").

### Exam-Ready Checklist: Binary Exploitation

- [ ] I can list the 6 argument registers in order: rdi, rsi, rdx, rcx, r8, r9
- [ ] I can draw a stack frame showing local variables, saved rbp, and return address
- [ ] I can explain what DEP, ASLR, and stack canary each prevent
- [ ] I can explain what a ROP gadget is and why it ends with `ret`
- [ ] I can construct a ret2libc chain for `system("/bin/sh")`
- [ ] I can construct a sys_execve chain with the correct register setup (rax=0x3b, rdi, rsi, rdx)
- [ ] I can convert an address to little-endian byte order
- [ ] I can compute absolute addresses from base address + offset

---

## Topic 2: Malware Analysis (Slide 06)

> **ASKED ON EXAM** — W2023/24, Exercise 5 (3+4+3 pts): *"Explain stack strings obfuscation; explain how to bypass anti-debugging using a debugger; explain C&C communication technique and advantages."*

### 2.1 Motivation and Infection Vectors

Malware analysis is performed to understand how malware works, to stop ongoing campaigns, and to develop countermeasures. Common infection vectors include malicious PDFs, phishing emails, malicious software updates, and Office document macros.

### 2.2 PDF Analysis

A PDF file is structured as a collection of objects, most of which are human-readable. Objects can be direct (like numbers, strings, and arrays) or indirect (identified by an ID number and generation number, enclosed between `obj` and `endobj` keywords).

The key object types are:
- **Name objects** begin with `/` (e.g., `/Launch`, `/JavaScript`)
- **Reference objects** point to other objects (e.g., `8 0 R`)
- **Strings** are written as `(literal text)` or `<hex encoded>`
- **Dictionaries** are enclosed in `<< >>` and contain key-value pairs

Every PDF has a **Catalog dictionary** that serves as the root of the document structure. The Catalog can contain an **OpenAction** entry, which specifies an action to execute automatically when the document is opened. This is how malicious PDFs deliver payloads without user interaction beyond opening the file.

The four security-relevant PDF actions are:

| Action | Effect |
|--------|--------|
| `/Launch` | Launches an external application |
| `/JavaScript` | Executes embedded JavaScript code |
| `/SubmitForm` | Sends form data to a specified URL |
| `/URI` | Opens a URI in the browser |

PDFs can be obfuscated through different string representations, stream compression, or object encryption. Analysis tools include text editors (since PDFs are mostly readable), `qpdf` for deobfuscation (decrypting and decompressing), and `peepdf` for a structural overview.

### 2.3 PE (Portable Executable) Analysis

Windows malware uses the PE format instead of ELF, and the Windows x64 calling convention (`fastcall`: rcx, rdx, r8, r9) instead of System V. The primary tools for PE analysis are x64dbg (dynamic analysis), and Ghidra or IDA (static analysis). Additional tools like PE Studio and Detect It Easy provide quick overviews of file properties.

There are two approaches to analyzing a PE binary:

- **Top-down approach:** Start at the program's entry point and follow the control flow step by step to understand the full execution path.
- **Bottom-up approach:** Search for interesting artifacts like API calls, strings, encryption routines, or network connections, and then trace backwards to understand how and when they are used.

The goal of both approaches is to understand the malware's behavior: what it does, what data it accesses, what network connections it makes, and what persistence mechanisms it uses.

### 2.4 Obfuscation: String Encryption

Strings in malware often contain sensitive information such as IP addresses, registry keys, URLs, and command-and-control server addresses. Because strings are easy to locate and read in a binary, malware authors encrypt them to make static analysis harder.

A common technique is **XOR encryption**, where each byte of the string is XORed with a fixed key byte. The encrypted bytes are stored in the binary's data section, and a decryption function runs at startup or just before the string is needed. For example:

```c
void xor_decrypt(unsigned char key, unsigned char *content) {
    for (int i = 0; content[i] != 0; ++i) {
        content[i] = content[i] ^ key;
    }
}
```

To deobfuscate encrypted strings, you can re-implement the decryption routine in Python and run it offline with the encrypted bytes and the key extracted from the binary.

### 2.5 Obfuscation: Stack Strings

> **ASKED ON EXAM** — W2023/24, Exercise 5a (3pts): *"Explain the obfuscation technique stack strings, what they are used for and why they work."*

Stack strings are an obfuscation technique where individual parts of a string are stored as separate integer values that are pushed onto the stack as local variables. Because the compiler allocates local variables in contiguous memory on the stack, these separate integers form a readable string when interpreted as a byte sequence at runtime.

For example, instead of writing `char ip[] = "169.254.0.33"`, the malware stores the IP address as:
```c
unsigned int ip_0 = 0;
unsigned int ip_1 = 0x33332e30;    // "03.3" in little-endian
unsigned int ip_2 = 0x2e343532;    // "254." in little-endian
unsigned int ip_3 = 0x2e393631;    // "169." in little-endian
```

Stack strings are used to hide sensitive strings from static analysis tools, which scan the binary's data section for readable text. They work because the string never appears as a single contiguous entity in the binary — it only materializes in memory at runtime when the stack variables are allocated next to each other.

To deobfuscate stack strings in Ghidra, you can retype the stack variables as a single character array, which causes the decompiler to display the combined string.

### 2.6 Anti-Debugging Techniques

Anti-debugging techniques detect whether a debugger is attached to the process and alter the program's behavior accordingly. If a debugger is detected, the malware typically exits or takes an evasive code path instead of executing its malicious payload.

**IsDebuggerPresent()** is a Windows API function from `debugapi.h` that returns `TRUE` if a user-mode debugger is attached to the calling process. Malware checks the return value and branches accordingly.

**Process Environment Block (PEB)** contains process context information, including a `BeingDebugged` flag at a known offset. Malware can read this flag directly using `__readgsqword(0x60)` to get the PEB address, then checking the `BeingDebugged` field. This approach avoids calling a detectable API function.

### 2.7 Anti-Debugging Circumvention

> **ASKED ON EXAM** — W2023/24, Exercise 5b (4pts): *"Given assembly instructions of main, explain how to use a debugger to circumvent anti-debugging and execute the target function."*

There are three main circumvention techniques:

**Patching:** Directly modify the conditional jump instruction in the binary so that the anti-debug branch is never taken. For example, change `je` (jump if equal) to `jmp` (unconditional jump) so it always skips the exit path.

**Modifying return values:** Set a breakpoint right after the `IsDebuggerPresent` call. When the breakpoint is hit, the return value is in `eax`. Change `eax` from 1 (debugger detected) to 0 (no debugger), then continue execution. The subsequent conditional check will behave as if no debugger is present.

**Modifying the instruction pointer:** Set a breakpoint at the conditional jump instruction. When hit, directly set `rip` (the instruction pointer) to the address of the target function, skipping the anti-debug check entirely.

**ScyllaHide** is a plugin for x64dbg that automatically hooks all common anti-debugging API calls and hides the debugger from detection.

**Example exam answer:** Given that `IsDebuggerPresent` is called at `0x140001487` and the result is tested at `0x140001489` (`test eax, eax`), with a conditional jump at `0x14000148b` (`je 0x140001497`): Set a breakpoint at `0x140001489`. When hit, set `eax` to 0 using the debugger. Continue execution — the `je` instruction will jump to `0x140001497`, which calls `super_secret_target_func`. Alternatively, set a breakpoint at `0x14000148b` and directly change `rip` to `0x140001497`.

### 2.8 Anti-Sandboxing Techniques

Anti-sandboxing techniques detect whether malware is running inside a virtual machine or automated analysis sandbox. The main categories are:

**File system artifacts:** Virtual machines leave specific files on the system, such as `System32\drivers\VBoxMouse.sys` or `System32\drivers\VBoxVideo.sys` for VirtualBox. Some researchers also give sample files names containing keywords like "sample" or "malware," which the malware can check.

**CPU instructions:** The CPUID instruction returns hardware information including a vendor name string. In a virtualized environment, this string is typically sandbox-specific (e.g., identifying VMware or VirtualBox). Some sandbox environments also fail to implement exotic or undocumented CPU instructions, which malware can use as a detection mechanism.

**Hardware detection:** VM device names are typically sandbox-specific and differ from real hardware. CPU temperature sensors are often unavailable in virtual environments, and audio devices may be missing. Malware checks for these indicators to decide whether to execute its payload or remain dormant.

Mitigations against anti-sandboxing include hardening tools like `antivmdetection` and `VBoxHardenedLoader`, as well as testing the sandbox setup against detection tools like `al-khaser` and `pafish`.

### 2.9 C&C Communication: Domain Flux

> **ASKED ON EXAM** — W2023/24, Exercise 5c (3pts): *"Explain the characteristic technique and two advantages compared to directly communicating with a hardcoded IP."*

Instead of communicating directly with a hardcoded IP address, sophisticated malware uses a technique called **domain flux** (or fast flux). The malware contains a **Domain Generation Algorithm (DGA)** that produces a large number of domain names based on a seed value (often derived from the current date). The malware tries to resolve these generated domains until it finds one that the C&C operator has actually registered and pointed to a server.

The two main advantages over a hardcoded IP are:

1. **Resilience against takedowns:** If defenders block one domain or shut down one server, the malware can simply move to another generated domain that resolves to a different IP address. There is no single point of failure.
2. **Difficulty of blocking:** Defenders cannot easily blacklist all possible domains because the DGA can generate thousands of new domains. Predicting and pre-emptively blocking all future domains requires reverse-engineering the DGA algorithm.

### Exam-Ready Checklist: Malware Analysis

- [ ] I can explain the four PDF actions (/Launch, /JavaScript, /SubmitForm, /URI) and what OpenAction does
- [ ] I can describe top-down vs bottom-up PE analysis approaches
- [ ] I can explain XOR string encryption and how to deobfuscate it
- [ ] I can explain stack strings: what they are, why they are used, and why they work
- [ ] I can explain IsDebuggerPresent and PEB-based anti-debugging
- [ ] I can describe 3 methods to circumvent anti-debugging in a debugger
- [ ] I can list the 3 main anti-sandboxing categories (filesystem, CPU, hardware)
- [ ] I can explain domain flux/DGA and give 2 advantages over hardcoded IPs

---

## Topic 3: Fuzzing (Slide 07)

> **ASKED ON EXAM** — W2022/23, Task 5 (2+4+4 pts) AND W2023/24, Exercise 7 (3+3+4 pts): *"When is instrumentation used? What vulnerabilities does ASan detect? Fill in the coverage-guided fuzzing diagram."* — This topic appeared on BOTH recent exams with near-identical questions.

### 3.1 What is Fuzzing?

Fuzzing is a software testing technique that feeds random or semi-random inputs to a program in order to discover bugs, crashes, and security vulnerabilities. It is a form of **robustness testing**, which checks whether unexpected or malformed inputs can cause the system to fail. Fuzzing was formalized in 1988 by Barton Miller at the University of Wisconsin.

### 3.2 Black-box, Grey-box, and White-box Testing

**White-box testing** assumes complete knowledge of the underlying source code. It uses analytical methods where the code is typically not executed, but instead examined statically for correctness.

**Black-box testing** assumes no knowledge of the source code. It uses dynamic methods where the program is executed with test inputs and the outputs are observed for unexpected behavior.

**Grey-box testing** combines techniques from both approaches. Coverage-guided fuzzing is a grey-box technique because it uses compile-time instrumentation (which requires source code access, a white-box technique) to guide the dynamic execution of random test inputs (a black-box technique).

### 3.3 Code Coverage Metrics

Code coverage measures what percentage of a program's code is exercised during testing. The main metrics, from simplest to most comprehensive, are:

- **Function coverage** tracks whether each function has been called at least once.
- **Line coverage** (or statement coverage) tracks whether each source code line has been executed.
- **Basic block coverage** tracks whether each basic block (a straight-line sequence of instructions with no internal branches) has been reached.
- **Branch coverage** tracks whether both the true and false outcomes of each conditional statement have been exercised.
- **Edge coverage** tracks which transitions (edges) in the control flow graph between basic blocks have been taken.
- **Path coverage** tracks which complete execution paths through the program have been followed. This is the most comprehensive but also the most computationally expensive metric.

Coverage-guided fuzzing typically uses edge or branch coverage, because these metrics capture how much of the program's logic has been tested while remaining computationally feasible.

### 3.4 The Control Flow Graph

A control flow graph (CFG) is a directed graph where vertices represent basic blocks and edges represent possible transfers of control flow between blocks. For example, an `if-else` statement creates two outgoing edges from the condition block — one for the true branch and one for the false branch. Coverage-guided fuzzing instruments the CFG to track which edges are exercised during each test run.

### 3.5 Instrumentation

> **ASKED ON EXAM** — W2022/23, Task 5a (2pts) AND W2023/24, Exercise 7a (3pts)

Instrumentation is performed at **compile time**, before the program is executed. During the instrumentation step, the compiler inserts additional tracking code (such as calls to `__sanitizer_cov_trace_pc`) at the beginning of each basic block in the program's control flow graph. These inserted calls record which basic blocks are reached during execution, enabling the fuzzer to measure code coverage and determine whether a new test input has discovered previously unseen code paths.

For **LibFuzzer**, instrumentation is done by compiling the target library with the flag `-fsanitize=fuzzer-no-link` (the `fuzzer-no-link` variant instruments the code without linking the fuzzer runtime, which is done separately when building the fuzz target). The fuzz target executable is compiled with `-fsanitize=fuzzer` to link the fuzzer runtime.

For **AFL++**, instrumentation is done by using AFL's custom compiler wrappers (`afl-clang-fast` or `afl-clang-fast++`) instead of the standard compiler. No special compiler flags are needed because the AFL compilers handle instrumentation automatically.

### 3.6 Address Sanitizer (ASan)

> **ASKED ON EXAM** — W2022/23, Task 5b (4pts) AND W2023/24, Exercise 7b (3pts)

The Address Sanitizer (ASan) is an instrumentation and runtime library developed by Google that detects memory safety vulnerabilities. It is enabled by adding `-fsanitize=address` to the compiler flags.

**What it detects:** ASan detects **stack buffer overflows**, **heap buffer overflows**, **heap use-after-free**, **use-after-scope**, **use-after-return**, and other memory safety violations.

**How it works:** ASan creates **poisoned redzones** — forbidden memory regions — around stack variables, global variables, and heap allocations. The instrumentation module inserts these redzones at compile time for stack and global objects. The runtime component replaces the standard memory allocator (`malloc`, `free`, etc.) to create redzones around heap allocations and to delay the reuse of freed memory regions. If the program reads from or writes to a redzone, ASan immediately reports the error with detailed diagnostic information (including the type of violation, the offending address, and the surrounding memory layout) and terminates the program.

**Practical implications:** ASan makes applications crash more easily so that hidden bugs become visible to the fuzzer. Combining ASan with fuzzing greatly improves the fuzzer's ability to find vulnerabilities, because many buffer overflows that would silently corrupt memory without ASan will now cause an immediate detectable crash. However, ASan significantly slows down execution (typically 2x–3x overhead), so it is common to run one fuzzer instance with ASan and one without, sharing the same corpus.

### 3.7 Coverage-Guided Fuzzing Algorithm

> **ASKED ON EXAM** — W2022/23, Task 5c (4pts) AND W2023/24, Exercise 7c (4pts)

The coverage-guided fuzzing algorithm is essentially a **genetic/evolutionary algorithm** applied to software testing. The flow is:

```
┌──────────────┐
│  Seed Files  │ ← Initial valid inputs
└──────┬───────┘
       ▼
┌──────────────────────┐
│  Code Coverage       │ ← Execute input, measure which code paths are hit
│  Evaluation          │
└──────┬───────────────┘
       ▼
┌──────────────┐     Yes    ┌────────┐
│   Crash?     │ ──────────→│  Done  │
│ (or ASan)    │            └────────┘
└──────┬───────┘
       │ No
       ▼
┌──────────────┐
│  Selection   │ ← Keep inputs that found new coverage
└──────┬───────┘
       ▼
┌──────────────┐
│  Mutation    │ ← Modify selected inputs to create new test cases
└──────┬───────┘
       │
       └──────→ (loop back to Code Coverage Evaluation)
```

The six labels that the exam asks you to assign are:

| Step | Label | Purpose |
|------|-------|---------|
| 1 | **Seed Files** | The initial set of valid input files that the fuzzer starts with |
| 2 | **Code Coverage Evaluation** | The instrumented program runs with the input and records which code paths were reached |
| 3 | **Crash (or ASan etc.)** | If the input causes a crash or ASan violation, it is saved as a finding and the fuzzer reports "Done" |
| 4 | **Selection** | Inputs that discovered new code coverage are kept in the corpus; others are discarded |
| 5 | **Mutation** | The selected inputs are modified using mutation strategies to create new test inputs |
| 6 | **Done** | The process terminates when a crash or violation is found |

The mapping to a genetic algorithm is:
- **Initial population** = seed files
- **Fitness function** = code coverage achieved by each input
- **Selection** = keep the fittest inputs (those with highest coverage)
- **Mutation** = modify inputs to explore new code paths
- **Termination** = crash found, ASan violation, timeout, or maximum number of runs reached

### 3.8 Seed Files

Providing good seed files significantly improves fuzzing performance. Seed files should be:

- **Valid inputs** for the target application, because valid inputs will reach deeper code paths more quickly than random garbage.
- **Small** (ideally under 1 KB), because smaller inputs process faster, yielding more executions per second.
- **Diverse**, covering different features and code paths of the target.

Existing unit test suites often include input files that make excellent seed files. For example, to fuzz an image parser, you would provide a set of small valid images in the seed directory.

### 3.9 Mutation Strategies

Mutation is one of the largest research areas in fuzzing. Basic mutation algorithms include:

- **Bitflips** randomly flip individual bits in the input.
- **Byte shuffling** rearranges bytes within the input.
- **String randomization** replaces parts of the input with random byte sequences.
- **Dictionary-based mutations** insert known interesting values (like boundary values, magic numbers, or format-specific keywords).

For applications that expect structured input (like JSON, XML, or network protocols), **grammar-based fuzzing** generates inputs that conform to the expected syntax but contain mutated payloads. This prevents the fuzzer from wasting time on inputs that are rejected immediately by the parser.

### 3.10 Practical Fuzzing with LibFuzzer

LibFuzzer requires you to write a fuzz target — a C/C++ function with the following signature:

```c
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Feed Data to the function under test
    return 0;  // non-zero return values are reserved
}
```

The fuzz target is compiled with `-fsanitize=fuzzer,address` and linked against the instrumented library. When run, LibFuzzer automatically generates mutated inputs, measures coverage, and reports crashes.

### 3.11 Practical Fuzzing with AFL++

AFL++ can fuzz any program that reads input from stdin or a file. The basic command is:

```
afl-fuzz -i seeds_dir -o output_dir -- ./instrumented_program
```

If the target program reads from a file instead of stdin, use `@@` as a placeholder for the file path:

```
afl-fuzz -i seeds_dir -o output_dir -- ./instrumented_program @@
```

AFL++ requires an initial seed directory containing at least one input file and an output directory for storing results.

### Exam-Ready Checklist: Fuzzing

- [ ] I can explain the difference between black-box, grey-box, and white-box testing
- [ ] I can list at least 4 code coverage metrics (line, branch, edge, path)
- [ ] I can explain when instrumentation is done and what it does (compile time, inserts tracking calls at each basic block)
- [ ] I can explain what ASan detects and how (poisoned redzones around stack/heap/global objects, replaces malloc/free)
- [ ] I can draw and label the coverage-guided fuzzing algorithm diagram with all 6 labels
- [ ] I can explain the role of seed files and mutation in the fuzzing loop
- [ ] I know the compiler flags for LibFuzzer (`-fsanitize=fuzzer-no-link,address`) and AFL++ (`afl-clang-fast++`)

---

## Active Recall Quiz

Test yourself on the key exam concepts from Phase 2. Try to answer each question before reading the answer.

### Q1: System V Calling Convention
**Question:** In what order are function arguments passed on 64-bit Linux? Where is the return value stored?

**Answer:** Arguments are passed in registers in this order: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`. Any additional arguments go on the stack. The return value is stored in `rax`.

### Q2: ROP Chain for execve
**Question:** What values must be in `rax`, `rdi`, `rsi`, and `rdx` to make an `execve("/bin/sh", NULL, NULL)` syscall?

**Answer:** `rax` must contain `0x3b` (the syscall number for execve). `rdi` must point to the string `"/bin/sh\0"`. Both `rsi` and `rdx` must be `0` (NULL), representing empty argv and envp arrays. A `syscall` instruction then triggers the kernel call.

### Q3: Stack Strings
**Question:** What are stack strings, why are they used, and why do they work?

**Answer:** Stack strings are an obfuscation technique where parts of a string are stored as separate integer local variables on the stack. They are used to hide sensitive strings (like IP addresses or registry keys) from static analysis tools. They work because the compiler allocates local variables contiguously on the stack, so at runtime these separate integers form a readable string in memory — but static analysis tools that scan the data section never see the string as a single entity.

### Q4: Anti-Debugging Bypass
**Question:** Given a binary that calls `IsDebuggerPresent` and exits if a debugger is found, describe two ways to bypass this using a debugger.

**Answer:** Method 1: Set a breakpoint immediately after the `IsDebuggerPresent` call and change the return value in `eax` from 1 to 0, then continue execution. The subsequent conditional check will behave as if no debugger is present. Method 2: Set a breakpoint at the conditional jump instruction and directly change the instruction pointer (`rip`) to skip the exit path and jump to the target function.

### Q5: ASan Detection Mechanism
**Question:** What vulnerabilities does the Address Sanitizer detect, and what mechanism does it use?

**Answer:** ASan detects stack buffer overflows, heap buffer overflows, use-after-free, and related memory safety violations. It works by creating poisoned redzones around stack, global, and heap objects. The instrumentation module inserts redzones at compile time for stack and global variables, while the runtime replaces `malloc` and `free` to create redzones around heap allocations. Any access to a redzone triggers an immediate crash with diagnostic information.

### Q6: Coverage-Guided Fuzzing Diagram
**Question:** List the six labels of the coverage-guided fuzzing algorithm in the correct order.

**Answer:** (1) Seed Files, (2) Code Coverage Evaluation, (3) Crash check (or ASan etc.), (4) Selection (keep inputs with new coverage), (5) Mutation (modify selected inputs), (6) Done (when crash is found). The flow loops from Mutation back to Code Coverage Evaluation.

### Q7: Domain Flux
**Question:** What is domain flux, and what are two advantages over using a hardcoded IP for C&C communication?

**Answer:** Domain flux is a technique where malware uses a Domain Generation Algorithm (DGA) to produce many domain names and tries to resolve them until finding one registered by the C&C operator. Advantage 1: Resilience against takedowns — blocking one domain does not disable the malware because it switches to another. Advantage 2: Difficulty of blocking — defenders cannot easily blacklist all possible domains since the DGA generates thousands of them.

### Q8: Instrumentation Timing
**Question:** When is instrumentation done in coverage-guided fuzzing, and what does it do?

**Answer:** Instrumentation is performed at compile time, before the program runs. The compiler inserts additional tracking calls (like `__sanitizer_cov_trace_pc`) at the beginning of each basic block in the program's control flow graph. These calls record which code paths are reached during execution, enabling the fuzzer to measure coverage and determine whether a new input discovered previously unseen paths.
