# Phase 1: Core Recurring Topics (~40 pts — CRITICAL)

**Slides covered:** 03 (Side Channels), 05 (Supply Chain & Threat Intel), 04 (Distributed Systems), 13 (Anonymization & SMPC)
**Exam evidence:** All 4 topics appeared on ALL 5 past written exams. These are worth ~40 guaranteed points.

---

## Topic 1: Side Channel Attacks (Slide 03)

> **ASKED ON EXAM** — S2019 (10pts), S2020 (10pts), S2021 (10pts), W2022/23 (10pts), W2023/24 (10pts): _5/5 exams, always 10 points_

### 1.1 Side Channels vs Covert Channels

A **side channel** is an unintentional information leakage that occurs through physical observables (such as timing, power consumption, or electromagnetic emissions) during a system's normal operation. The system designer never intended for this channel to exist. An attacker passively observes these leakages to extract secret information. For example, an attacker can measure the CPU's power consumption during RSA decryption to reveal individual key bits.

A **covert channel** is an intentional communication channel that an attacker deliberately establishes by encoding information into a system's observable behavior. Unlike a side channel, the attacker actively creates this channel to exfiltrate data. For example, malware could encode stolen data in the timing patterns of DNS queries to secretly transmit it to an external server.

The key distinction is intent: side channels are **unintentional** and exploited by the attacker, while covert channels are **intentionally established** by the attacker.

### 1.2 Types of Side Channels

There are several types of side channels, each based on a different physical observable:

- **Timing side channels** exploit differences in execution time. For instance, the RSA square-and-multiply algorithm takes longer when performing a multiply step, which reveals whether a key bit is 1 or 0.
- **Power side channels** exploit variations in power consumption. Different CPU instructions draw different amounts of current, so power traces can reveal what operations are being performed.
- **Electromagnetic side channels** exploit EM emissions radiated by electronic components. These are the basis of TEMPEST attacks.
- **Cache side channels** exploit timing differences between cache hits and cache misses. Flush+Reload, Prime+Probe, and Spectre all belong to this category.
- **Acoustic side channels** exploit sounds produced by hardware, such as coil whine during cryptographic operations.
- **Error message side channels** exploit observable differences in server responses, such as the padding oracle attack which distinguishes between invalid padding and invalid content errors.

### 1.3 Why Side Channels Are Exploitable

Side channels exist because of three factors:

1. **Data-dependent computation:** Different secret inputs cause the system to behave differently in terms of physical characteristics such as timing or power draw.
2. **Shared resources:** The attacker and victim share hardware resources like the CPU cache or memory bus, which allows the attacker to observe the victim's behavior indirectly.
3. **Observable physical effects:** Physical properties like timing, power consumption, and electromagnetic emissions can be measured from outside the system without the system being aware.

### 1.4 Advantage Over Brute Force

> **ASKED ON EXAM** — S2020 (b), S2021 (b), W2022/23 (b)

The complexity of brute-forcing a cryptographic algorithm depends on the **key space**, which grows exponentially with key length. For an n-bit key, brute force requires searching through up to 2^n possible keys.

In contrast, the complexity of a side channel attack depends on the **key length** itself, which grows only linearly. An attacker needs roughly n observations to recover an n-bit key, one observation per bit.

This means side channels reduce the problem from searching an exponential key space to making a linear number of observations. This is a dramatic advantage that makes otherwise secure algorithms vulnerable.

### 1.5 Power Analysis (SPA / DPA / CPA)

> **ASKED ON EXAM** — W2022/23 (c): "Why does measuring power consumption leak information? Give two examples."

Measuring power consumption leaks information because different CPU instructions consume different amounts of power. When the CPU performs data-dependent operations like conditional branches or multiplications, these operations create measurable power signatures that correlate with the secret data being processed.

**Simple Power Analysis (SPA)** works by directly reading key bits from a single power trace. For example, in RSA's square-and-multiply algorithm, multiply operations consume noticeably more power than square-only operations. An attacker can look at one power trace and directly determine which key bits are 1 (multiply+square) and which are 0 (square only).

**Differential Power Analysis (DPA)** uses many power traces combined with statistical analysis. The attacker collects traces from many encryptions, hypothesizes about specific key bits, and uses the difference of means to determine which hypothesis is correct.

**Correlation Power Analysis (CPA)** extends DPA by computing the Pearson correlation between measured power values and a predicted power model. It is more efficient and requires fewer traces than DPA.

**Two exam-ready examples of power consumption leaking information:**

1. In RSA's square-and-multiply algorithm, multiply operations consume more power than square-only operations. The power trace directly reveals which key bits are 1 versus 0.
2. In AES, the power consumption during S-box table lookups correlates with the Hamming weight of the processed data. This leaks information about the key bytes being used.

### 1.6 Padding Oracle Attack (THE MOST TESTED CONCEPT)

> **ASKED ON EXAM** — ALL 5 exams in various forms

The padding oracle attack relies on three elements. Missing any one of them in your exam answer will cost 2-3 points:

1. **CBC mode encryption:** In CBC mode, each plaintext block is XORed with the previous ciphertext block before encryption. During decryption, this means: $P_i = D_k(C_i) \oplus C_{i-1}$.
2. **PKCS#7 padding:** The last block of plaintext is padded so that the last byte indicates the padding length. Valid padding looks like: 01, or 02 02, or 03 03 03, and so on.
3. **Error oracle:** The server responds differently to invalid padding versus invalid content. This difference in behavior is the side channel that the attacker exploits.

**How the attack works:**

The attacker targets the last byte of a plaintext block P*i. They systematically modify the last byte of the preceding ciphertext block C*{i-1}, trying all 256 possible values (0x00 through 0xFF). For each modified value, they send the pair (C\_{i-1}', C_i) to the server.

The server decrypts this as: $P_i' = D_k(C_i) \oplus C_{i-1}'$.

When the server reports "valid padding," the attacker knows the last byte of $P_i'$ equals $0x01$. From this, the attacker can compute $D_k(C_i)[\text{last}] = C_{i-1}'[\text{last}] \oplus 0x01$, and then recover $P_i[\text{last}] = D_k(C_i)[\text{last}] \oplus C_{i-1}[\text{last}]$.

The attacker then repeats this process for each byte position by setting the target padding to 0x02, 0x03, and so on, eventually recovering the entire plaintext block. The process is repeated for all blocks.

**What is leaked:** The server reveals whether the PKCS#7 padding is valid or not. This is just 1 bit of information per query.

**What the attacker ultimately obtains:** The entire plaintext is recovered byte by byte, without ever knowing the encryption key.

**Interesting targets:** Any system that uses CBC mode encryption and returns distinguishable errors for bad padding versus bad content. This includes web applications, TLS implementations, and APIs.

**Maximum number of queries:** At most 256 attempts per byte, multiplied by the block size in bytes, multiplied by the number of blocks.

### 1.7 Rowhammer

> **ASKED ON EXAM** — W2022/23 (a): "Give two examples where flipping a single bit compromises security"

Rowhammer is a hardware vulnerability in DRAM. By repeatedly accessing (hammering) specific memory rows at high speed, the attacker causes electrical interference that flips bits in physically adjacent rows. The system does not detect that a bit has been changed.

**Two examples where flipping a single bit compromises security:**

1. **Page table entry bit flip:** The attacker flips a permission bit in a page table entry, changing a read-only page to read-write. This gives the attacker write access to protected memory such as kernel memory, leading to privilege escalation.
2. **Authentication flag bit flip:** The attacker flips a bit in an "is_admin" or "authenticated" flag stored in memory. This can bypass authentication and grant unauthorized access.

### 1.8 Cache Side Channels: Flush+Reload vs Prime+Probe

**Flush+Reload** requires the attacker and victim to share memory (for example, through a shared library). The attacker first flushes a specific cache line, then waits for the victim to execute, and finally reloads that cache line while measuring the access time. If the reload is fast, it means the victim accessed that memory location, causing it to be cached again.

**Prime+Probe** does not require shared memory. The attacker first fills an entire cache set with their own data (this is the "prime" step). Then they wait for the victim to execute. Finally, the attacker accesses their own data again (the "probe" step) and measures the access time. If the access is slow, it means the victim evicted the attacker's data from the cache set, which reveals that the victim accessed memory that maps to the same cache set.

Flush+Reload operates at cache line granularity and is more precise. Prime+Probe operates at cache set granularity but works in more scenarios because it does not require shared memory.

### 1.9 Spectre and Meltdown

Both Spectre and Meltdown exploit speculative execution combined with the fact that the CPU cache is a shared microarchitectural resource that retains state even after speculation is rolled back.

**Spectre** exploits branch prediction. The CPU speculatively executes instructions along a mispredicted branch, and during this speculative window, it accesses secret data that gets loaded into the cache. Even though the CPU rolls back the computation, the cache state remains, allowing the attacker to extract the secret data through a cache side channel. Spectre works across processes at the same privilege level. It is mitigated by techniques like Retpoline and IBRS.

**Meltdown** exploits out-of-order execution. The CPU performs a memory access before the permission check completes, temporarily loading kernel memory into a register. Although the CPU later raises a fault, the data has already been cached. The attacker uses a cache side channel to read the cached data. Meltdown allows reading kernel memory from user space. It is mitigated by KPTI (Kernel Page Table Isolation), which separates kernel and user page tables.

Three factors contribute to both attacks: (1) speculative or out-of-order execution, (2) the cache being a shared resource between attacker and victim, and (3) no rollback of cache state after speculation is aborted.

**Cache-Rollback defense idea (from Exercise 3d):** One proposed defense is to mark speculatively loaded cache entries as uncached and roll them back if the speculation was wrong. However, this does not fully work because the attacker can still observe timing differences during the speculation window itself, before any rollback occurs.

### 1.10 Side Channels in Code (Exercise 3e)

Consider the following code:

```c
while (secret >>= 1) {
    if (secret & 0x1) odd();
    else even();
}
```

This code has multiple potential side channels. A **timing side channel** exists if the `odd()` and `even()` functions take different amounts of time to execute. A **cache side channel** exists because calling `odd()` versus `even()` accesses different code locations, leaving different patterns in the cache. A **power side channel** exists because different instructions consume different amounts of power.

### 1.11 Countermeasures

- **TEMPEST shielding** protects against electromagnetic side channels by physically shielding equipment to prevent EM emissions from leaking.
- **Constant-time code** protects against timing attacks by ensuring that all code paths take the same amount of time regardless of the secret data.
- **Masking and blinding** protect against power analysis by randomizing intermediate values so that power consumption does not correlate with the secret.
- **Cache partitioning** protects against cache attacks by isolating cache regions between different processes.
- **KPTI** protects against Meltdown by separating kernel and user page tables.
- **Retpoline** protects against Spectre by replacing indirect branches with a construct that prevents speculative execution of the target.

### Exam-Ready Checklist — Side Channels

- [ ] Define side channel vs covert channel in complete sentences
- [ ] State the advantage over brute force (linear vs exponential complexity)
- [ ] Explain the padding oracle attack: name the three elements (CBC, PKCS#7, error oracle) and describe the recovery formula $P_i = D(C_i) \oplus C_{i-1}$
- [ ] Give two Rowhammer examples where a single bit flip compromises security
- [ ] Explain why power consumption leaks information and give two concrete examples
- [ ] Compare Flush+Reload and Prime+Probe (shared memory requirement, mechanism, granularity)
- [ ] Explain Spectre vs Meltdown (what each exploits, scope, mitigations)

**Drill these definitions until you can write them blind.**

---

## Topic 2: Supply Chain & Threat Intelligence (Slide 05)

> **ASKED ON EXAM** — S2019 (10pts), S2020 (10pts), S2021 (10pts), W2022/23 (10pts), W2023/24 (10pts): _5/5 exams, always 10 points_

### 2.1 CIA Triad

> **ASKED ON EXAM** — W2022/23 (a), W2023/24 (a): "Name the key concepts of information security and define each in one sentence"

The three key concepts of information security are:

- **Confidentiality** means that information is accessible only to those who are authorized to access it.
- **Integrity** means that information has not been modified by unauthorized parties and remains accurate and complete.
- **Availability** means that information and systems are accessible to authorized users whenever they are needed.

### 2.2 Threat Actor Types & Motivations

> **ASKED ON EXAM** — S2019 (a), S2020 (c), S2021 (b), W2022/23 (b), W2023/24 (d): _5/5 exams_

There are six main types of threat actors, each driven by a different primary motivation:

- **Nation states** are motivated by geopolitical advantage and espionage. They conduct cyber operations to further national interests.
- **Cyber criminals** are motivated by financial gain. They steal data, deploy ransomware, or commit fraud for profit.
- **Hacktivists** are motivated by ideological or political agendas. They use cyberattacks to promote a social or political cause.
- **Cyber terrorists** are motivated by causing fear and disruption for political goals. They aim to create terror through attacks on critical infrastructure.
- **Thrill seekers (script kiddies)** are motivated by personal satisfaction, curiosity, or reputation. They attack systems for the challenge or bragging rights.
- **Insider threats** are motivated by revenge, financial gain, or coercion. They exploit their legitimate access to cause harm from within an organization.

### 2.3 APTs (Advanced Persistent Threats)

> **ASKED ON EXAM** — W2023/24 (d): "What are APTs and what characterizes them?"

An APT is a type of cyberattack characterized by three properties:

- **Advanced** means the attacker uses sophisticated tools, techniques, and procedures (TTPs). APT groups often develop custom malware and exploit zero-day vulnerabilities.
- **Persistent** means the attacker maintains access to the target for long periods, often months or years. They use a low-and-slow approach to avoid detection.
- **Threat** means the attacker is well-funded and organized, with specific strategic objectives. APT groups typically operate at nation-state level resources.

APTs are further characterized by strategic patience, targeting of specific high-value targets, use of multiple attack vectors, and the ability to adapt their techniques when discovered.

### 2.4 Intrusion Kill Chain (7 Phases)

> **ASKED ON EXAM** — S2020 (a), S2021 (b), W2022/23 (c), W2023/24 (b): _4/5 exams_

The Intrusion Kill Chain describes the seven sequential phases of a cyberattack:

1. **Reconnaissance:** The attacker gathers information about the target using techniques like OSINT and footprinting.
2. **Weaponization:** The attacker creates an attack payload by combining an exploit with a backdoor, for example packaging malware inside a PDF document.
3. **Delivery:** The attacker transmits the payload to the target through a channel such as a phishing email, a USB drive, or a compromised website.
4. **Exploitation:** The payload is triggered on the target system. This happens when the exploit is executed, for example when the victim opens a malicious file.
5. **Installation:** The attacker installs a persistent backdoor on the compromised system to maintain access.
6. **Command & Control (C2):** The attacker establishes a communication channel from the compromised system back to their infrastructure, allowing remote control.
7. **Actions on Objectives:** The attacker achieves their goal, which may include exfiltrating data, disrupting operations, or moving laterally to other systems.

### 2.5 Footprinting (Trick Question!)

> **ASKED ON EXAM** — W2022/23 (d): "Is scanning the target's public server for open ports a suitable technique for footprinting?"

Footprinting is a reconnaissance technique that uses only external or third-party sources to gather information about a target. The defining characteristic of footprinting is that there is **no direct interaction** with the target system. Examples of footprinting include WHOIS lookups, public DNS queries, reviewing social media profiles, reading job postings, and consulting public records.

**The trick question answer:** Scanning the target's server for open ports is **NOT** footprinting. Port scanning involves sending packets directly to the target, which constitutes active reconnaissance and direct interaction. Footprinting is strictly passive and relies only on publicly available information gathered without touching the target.

### 2.6 Pyramid of Pain

> **ASKED ON EXAM** — S2019 (b, 6pts), S2020 (b), S2021 (a)

The Pyramid of Pain visualizes how much difficulty ("pain") it causes an attacker when a defender detects and blocks each type of Indicator of Compromise (IoC). The pyramid has six levels, ordered from easiest to change at the bottom to hardest to change at the top:

```
        /  TTPs  \          ← Hardest to change
       / Tools    \
      / Network/   \
     / Host Artifacts\
    / Domain Names    \
   / IP Addresses      \
  / Hash Values         \  ← Easiest to change
```

- **Hash values** are at the bottom because the attacker can trivially change them by recompiling their malware.
- **IP addresses** are easy to change by switching to a different server.
- **Domain names** are somewhat annoying to change because the attacker must register new domains.
- **Network and host artifacts** (like registry keys or user-agent strings) are frustrating to change because they often require modifying the malware's behavior.
- **Tools** are challenging to change because the attacker must rewrite or replace their custom malware and frameworks.
- **TTPs** (tactics, techniques, and procedures) are at the top because they represent the attacker's fundamental behavior patterns, which are very hard to change without completely redesigning the attack methodology.

### 2.7 Supply Chain Attacks

> **ASKED ON EXAM** — S2019 (c), S2020 (d), S2021 (c), W2023/24 (c): _4/5 exams_

A supply chain attack occurs when an attacker compromises a trusted component in the software supply chain — such as a library, build tool, update mechanism, or code repository — in order to distribute malicious code to downstream consumers who trust that source. The attack is effective because victims have no reason to suspect the compromised component, since it comes from a legitimate and previously trusted source.

Common supply chain attack techniques include:

- **Typosquatting:** The attacker registers package names that are similar to popular legitimate packages. For example, registering "crossenv" to impersonate the legitimate "cross-env" package.
- **Watering hole attacks:** The attacker compromises a website that is frequently visited by the target group, infecting visitors who trust the site.
- **Dependency confusion:** The attacker uploads a malicious package to a public registry using the same name as an organization's internal package, causing build systems to download the public (malicious) version instead.
- **Compromised build pipelines:** The attacker injects malicious code directly into a project's build or CI/CD pipeline.

A real-world example is the event-stream incident of 2018, where an attacker gained maintainer access to a popular npm package and added a malicious dependency that specifically targeted a Bitcoin wallet application.

### Exam-Ready Checklist — Supply Chain & Threat Intel

- [ ] Define the three CIA concepts in one complete sentence each
- [ ] List all six threat actor types with their primary motivations
- [ ] Define APT by explaining what Advanced, Persistent, and Threat each mean
- [ ] List the seven Kill Chain phases in order with a one-sentence description of each
- [ ] Define footprinting and explain why port scanning is NOT footprinting
- [ ] Draw the Pyramid of Pain with all six levels from bottom to top
- [ ] Define supply chain attacks and name at least two specific techniques

**Drill these definitions until you can write them blind.**

---

## Topic 3: Security of Distributed Systems (Slide 04)

> **ASKED ON EXAM** — S2019 (10+10pts), S2020 (10+10pts), S2021 (10+10+10pts), W2022/23 (10+10+10pts), W2023/24 (10pts): _5/5 exams, 10-30 points_

### 3.1 Needham-Schroeder Protocol (Centralized Key Management)

> **ASKED ON EXAM** — W2022/23 (Task 6): "Write down the Needham-Schroeder protocol" (6 pts) + "Explain weakness with stolen session key" (4 pts)

The Needham-Schroeder protocol establishes a pairwise session key between two users through a trusted third party called the Group Controller (GC). User u1 has identity ID1 and shares a secret key k*{1,GC} with the GC. User u2 has identity ID2 and shares a secret key k*{2,GC} with the GC.

The protocol consists of five messages:

$$
\begin{align*}
1.\quad & u_1 \rightarrow GC &&: ID_1, ID_2, n_1 \\
2.\quad & GC \rightarrow u_1 &&: E(\{n_1, k_{12}, ID_2, E(\{k_{12}, ID_1\}, k_{2,GC})\}, k_{1,GC}) \\
3.\quad & u_1 \rightarrow u_2 &&: E(\tilde{n}_1, k_{12}), E(\{k_{12}, ID_1\}, k_{2,GC}) \quad \text{(ticket)} \\
4.\quad & u_2 \rightarrow u_1 &&: E(\{\tilde{n}_1-1, n_2\}, k_{12}) \\
5.\quad & u_1 \rightarrow u_2 &&: E(\{n_2-1\}, k_{12})
\end{align*}
$$

The nonces $n_1$ and $n_2$ serve as protection against replay attacks. Message 2 contains a **ticket** — the encrypted package $E(\{k_{12}, ID_1\}, k_{2,GC})$ — which $u_1$ cannot read because it is encrypted with $u_2$'s key. In message 3, $u_1$ forwards this ticket to $u_2$ so that $u_2$ can extract the session key $k_{12}$. Messages 4 and 5 provide mutual authentication, as both parties prove they possess the session key.

**Weakness:** If the session key $k_{12}$ is **stolen** by an attacker, the attacker can replay message 3 to $u_2$ at any later time. Since the ticket does not contain a timestamp, $u_2$ cannot distinguish this replayed message from a fresh session. The attacker can then complete the handshake using the stolen key. The Kerberos protocol fixes this weakness by adding timestamps to the messages.

The Needham-Schroeder protocol has three main disadvantages:

1. The Group Controller is a **single point of failure** — if it goes down, no new keys can be established.
2. It does not support network partition and merge operations.
3. Pairwise key establishment has **limited scalability** because the number of required keys grows as n(n-1)/2, which is O(n^2).

### 3.2 Diffie-Hellman Key Exchange

The Diffie-Hellman algorithm allows two users to generate a shared secret key over public channels. It works in the multiplicative group $\mathbb{Z}_p^*$, where $p$ is a large prime and $g$ is a generator of the group.

Each user generates a secret key and computes a corresponding blind key (also called a public DH key). User $u_1$ generates secret key $k_1$ and computes blind key $bk_1 = g^{k_1} \pmod p$. User $u_2$ generates secret key $k_2$ and computes blind key $bk_2 = g^{k_2} \pmod p$. They exchange their blind keys publicly.

After the exchange, $u_1$ computes the shared key as $k_{12} = bk_2^{k_1} \pmod p = g^{k_1 \cdot k_2} \pmod p$. User $u_2$ independently computes $k_{12} = bk_1^{k_2} \pmod p = g^{k_1 \cdot k_2} \pmod p$. Both arrive at the same shared secret.

Two shorthand notations are used throughout the TGDH protocol:

- $BK(k) = g^k \pmod p$ computes the blind key from a secret key.
- $DH(bk, k) = bk^k \pmod p$ computes the shared key from the other party's blind key and one's own secret key.

### 3.3 TGDH (Tree-based Group Diffie-Hellman) Protocol

> **ASKED ON EXAM** — S2020 (5d), S2021 (5d), W2022/23 (7a): "Write down the group key calculation of user u_i"

TGDH is a distributed group key management protocol that does not require a central controller. Users are arranged in a binary tree, and the Diffie-Hellman algorithm is applied iteratively from the leaves up to the root. The key stored at the root is the group key used for encrypting communications.

```
              k_{0,0}   ← GROUP KEY (root)
             /        \
        k_{1,0}      k_{1,1}
        /    \       /     \
    k_{2,0} k_{2,1} k_{2,2} k_{2,3}
      u1      u2     u3      u4
```

Each user generates a secret key at their leaf node and computes the corresponding blind key using $BK(k) = g^k \pmod p$. Every user knows the blind keys of all other tree nodes, but only their own secret key. To compute a parent node's key, a user applies the DH function using the sibling's blind key and the child node's key they already know. This process is repeated up the tree until the root (group key) is reached.

**Group key calculation by $u_3$:** User $u_3$ knows their own secret key $k_{2,2}$ and the blind keys $bk_{2,3}$ and $bk_{1,0}$. First, $u_3$ computes $k_{1,1} = DH(bk_{2,3}, k_{2,2}) = bk_{2,3}^{k_{2,2}} \pmod p$. Then $u_3$ computes the group key $k_{0,0} = DH(bk_{1,0}, k_{1,1}) = bk_{1,0}^{k_{1,1}} \pmod p$.

**Group key calculation by $u_4$:** User $u_4$ knows their own secret key $k_{2,3}$ and the blind keys $bk_{2,2}$ and $bk_{1,0}$. First, $u_4$ computes $k_{1,1} = DH(bk_{2,2}, k_{2,3}) = bk_{2,2}^{k_{2,3}} \pmod p$. Then $u_4$ computes the group key $k_{0,0} = DH(bk_{1,0}, k_{1,1}) = bk_{1,0}^{k_{1,1}} \pmod p$.

**Group key calculation by $u_1$:** User $u_1$ knows their own secret key $k_{2,0}$ and the blind keys $bk_{2,1}$ and $bk_{1,1}$. First, $u_1$ computes $k_{1,0} = DH(bk_{2,1}, k_{2,0}) = bk_{2,1}^{k_{2,0}} \pmod p$. Then $u_1$ computes the group key $k_{0,0} = DH(bk_{1,1}, k_{1,0}) = bk_{1,1}^{k_{1,0}} \pmod p$.

**JOIN operation:** When a new user wants to join, they send a JoinRequest via IP multicast. The **sponsor** is the existing user whose leaf node is split to accommodate the new user. The sponsor computes all new keys along the path from the split point up to the root, then broadcasts the updated blind keys. All other members use these new blind keys to recalculate the group key.

**LEAVE operation:** When a user leaves, they send a LeaveRequest. The **sponsor** is the sibling of the leaving user in the key tree. The sponsor generates a fresh random secret key (which ensures backward secrecy), computes new keys all the way up to the root, and broadcasts the updated blind keys.

TGDH provides three security properties: **forward secrecy** ensures that a newly joining user cannot derive old group keys; **backward secrecy** ensures that a leaving user cannot derive the new group key because the sponsor refreshes their key; and there is **no single point of failure** since there is no central controller.

### 3.4 LKH (Logical Key Hierarchy) — Centralized Tree Key Management

> **ASKED ON EXAM** — S2019 (4a,4b,4c), S2020 (5a,5b,5c), S2021 (5a,5b,5c): "keys known by user" + "draw modified tree" + "broadcast message on leave"

LKH is a centralized group key management protocol that uses a tree structure managed by a Group Controller (GC). Unlike TGDH, which is distributed and uses DH computations, LKH relies on the GC to assign and distribute keys.

The key difference between LKH and TGDH is what each user knows. In TGDH, each user knows their own secret key and the blind keys of all other nodes. In LKH, each user knows **all the keys on the path from their leaf to the root**. The GC knows every key in the tree.

```
              k_{0,0}   ← group key
             /        \
        k_{1,0}      k_{1,1}
        /    \       /     \
    k_{2,0} k_{2,1} k_{2,2} k_{2,3}
      u1      u2     u3      u4
```

For example, user $u_1$ knows $k_{2,0}$, $k_{1,0}$, and $k_{0,0}$. User $u_3$ knows $k_{2,2}$, $k_{1,1}$, and $k_{0,0}$. User $u_4$ knows $k_{2,3}$, $k_{1,1}$, and $k_{0,0}$.

**LKH Leave (group-oriented rekeying):** When a user leaves, all keys on the path from their leaf to the root must be replaced. The GC generates new keys and broadcasts them encrypted with keys that only the remaining members possess.

For example, suppose $u_2$ leaves. The keys $k_{2,1}$, $k_{1,0}$, and $k_{0,0}$ must all change. The GC generates new keys $\tilde{k}_{1,0}$ and $\tilde{k}_{0,0}$ and broadcasts:

$$
\{ E(\tilde{k}_{1,0}, k_{2,0}), \quad E(\tilde{k}_{0,0}, \tilde{k}_{1,0}), \quad E(\tilde{k}_{0,0}, k_{1,1}) \}
$$

User $u_1$ can decrypt $\tilde{k}_{1,0}$ using $k_{2,0}$ (which they know), and then decrypt $\tilde{k}_{0,0}$ using $\tilde{k}_{1,0}$. Users $u_3$ and $u_4$ can decrypt $\tilde{k}_{0,0}$ directly using $k_{1,1}$, which has not changed. The departed user $u_2$ cannot obtain any new key because they do not possess $k_{2,0}$ or $k_{1,1}$.

### 3.5 Secret Sharing — Two Types

> **ASKED ON EXAM** — S2019, S2020, S2021, W2023/24: "Write down different types of secret sharing"

There are two main types of secret sharing:

**Linear secret sharing (n-out-of-n)** requires all $n$ users to participate in order to reconstruct the secret. The secret is split into $n$ shares, and reconstruction is done by adding all shares together: $s = s_1 + s_2 + ... + s_n$. An example is the n-out-of-n RSA multi-signature scheme.

**Threshold secret sharing (k-out-of-n)** requires only $k$ out of $n$ users to participate. Any group of $k$ users can reconstruct the secret using Lagrange interpolation, but any group of fewer than $k$ users learns nothing about the secret. Shamir's Secret Sharing is the standard example of this type.

### 3.6 Shamir's Secret Sharing — (k,n) Threshold

> **ASKED ON EXAM** — W2023/24 (6b): "Write down the operation to restore the secret"

Shamir's Secret Sharing is a $(k,n)$ threshold algorithm. A trusted dealer holds a secret $a_0$ (such as a secret key) and wants to distribute it among $n$ users so that any $k$ of them can reconstruct it.

The dealer chooses $k-1$ random coefficients $a_1, ..., a_{k-1}$ from $\mathbb{Z}_p$ and constructs a polynomial of degree $k-1$:

**$f(x) = a_0 + a_1 \cdot x + \dots + a_{k-1} \cdot x^{k-1} \pmod p$**

The secret $a_0$ is the constant term of this polynomial. The dealer gives each user $u_i$ a share consisting of the pair $(x_i, s_i = f(x_i) \pmod p)$, where $x_i = i$ is public and $s_i$ must be kept secret.

To reconstruct the secret, any $k$ users apply Lagrange interpolation at $x = 0$:
$$ a*0 = f(0) = \sum*{j=1}^{k} s*j \cdot \prod*{i \neq j} \frac{x_i}{x_i - x_j} \pmod p $$

The crucial property is that any $k$ shares are sufficient to reconstruct the secret, while any fewer than $k$ shares reveal absolutely nothing about it.

### 3.7 n-out-of-n RSA Multi-Signature

> **ASKED ON EXAM** — S2019 (5b,5c), S2020 (4b,4c), S2021 (6b,6c): "Write RSA multi-sig equations + verification"

In an n-out-of-n RSA multi-signature scheme, $n$ users jointly sign a message $m$. The public key is $(e, \bar{n})$, each user $u_i$ holds a partial secret key $(d_i, \bar{n})$, and the modulus is $\bar{n} = p \cdot q$ where $p$ and $q$ are large primes.

**Signing:** First, the message is hashed: $M = H(m)$. Then each user $u_i$ computes their partial signature: $s_i = M^{d_i} \pmod{\bar{n}}$.

**Reconstruction:** The combined signature is the product of all partial signatures: $s = \prod_{i=1}^{n} s_i \pmod{\bar{n}}$.

**Verification:** The verifier checks whether $H(m)$ equals $s^e \pmod{\bar{n}}$. If they match, the signature is valid.

This works because the partial keys satisfy $d_1 + d_2 + ... + d_n = d$ (the full private key), so multiplying the partial signatures is equivalent to signing with the full key. Applications include e-voting systems and DNSSEC root zone signing (which uses a 5-of-7 threshold).

### 3.8 E-Voting System (4 Steps)

> **ASKED ON EXAM** — W2022/23 (Task 8, 10pts), W2023/24 (6c, 6pts): "Describe the four steps of an e-voting system"

The e-voting system combines two mechanisms: the n-out-of-n RSA signature scheme and blind signatures. A blind signature allows an authority to sign a message without knowing its content.

In a blind RSA signature, the user chooses a random number $r$ with $\gcd(r, \bar{n}) = 1$ and computes the blinded message $m' = r^e \cdot m \pmod{\bar{n}}$. The authority signs the blinded message: $s' = (m')^d \pmod{\bar{n}}$. The user then unblinds the signature: $s = s' \cdot r^{-1} \pmod{\bar{n}}$, which equals $m^d \pmod{\bar{n}}$ — a valid signature on the original message.

The e-voting system works in four steps:

**Step 1 — Voting and Blinding:** The voter has a vote $x$ and chooses a random number $r$. The voter computes the blinded vote $x' = r^e \cdot x \pmod{\bar{n}}$ and sends $x'$ to all $n$ authorities.

**Step 2 — Signing by Authorities:** Each authority $A_i$ uses their partial secret key $d_i$ to sign the blinded vote: $s'_i = (x')^{d_i} \pmod{\bar{n}}$. Each authority sends their partial signature back to the voter.

**Step 3 — Unblinding:** The voter multiplies all partial signatures to get the combined blinded signature: $s' = \prod s'_i \pmod{\bar{n}}$. Then the voter unblinds: $s = s' \cdot r^{-1} \pmod{\bar{n}}$. The voter now sends the pair $(s, x)$ to one of the authorities using **anonymous communication** (such as TOR) so that the vote cannot be traced back to the voter.

**Step 4 — Verification and Counting:** The receiving authority verifies the signature by checking whether $x = s^e \pmod{\bar{n}}$. If the verification passes, the vote $x$ is counted.

### 3.9 Blockchain / Distributed Ledger

> **ASKED ON EXAM** — S2021 (Task 7, 10pts): "What is a blockchain? What is the task of miners? Describe operation."

A blockchain is a distributed ledger technology where data records are organized into blocks, each block is cryptographically linked to the previous block through a hash, and every participant in the network holds a complete copy of the ledger. This design makes the ledger tamper-resistant because altering any block would invalidate all subsequent blocks.

Each Bitcoin block consists of a header and a body. The header contains the version, the hash of the previous block, the Merkle root hash, a timestamp, the difficulty parameter, and a nonce. The body contains a list of transactions. A **Merkle tree** is a binary tree constructed from the hashes of all transactions in the block, with the root hash included in the header. This structure enables efficient proof that a specific transaction is included in a block.

**The Bitcoin operation follows six steps:**

1. Users create and digitally sign their transactions, then broadcast them to the network.
2. Mining nodes receive these transactions and cache them in a **memory pool (mempool)**. A mining node selects verified transactions and assembles them into a **candidate block**, checking that all signatures are authentic and all transactions are valid.
3. The candidate block is shared across the Bitcoin network.
4. All mining nodes compete to solve a **search puzzle (Proof of Work)** for the candidate block.
5. The first miner to solve the puzzle broadcasts the valid block to the network.
6. Other mining nodes accept the new block and use its hash as the "previous block hash" for the next candidate block.

**Proof of Work (PoW)** means finding a nonce value such that Hash(block header including nonce) is less than the current difficulty target. This requires brute-force searching through many nonce values, and there is no shortcut to find the solution.

Bitcoin uses a **transaction-based ledger (UTXO model)**. Each transaction has inputs (TxIn) that reference unspent outputs from previous transactions, and outputs (TxOut) that specify recipients and amounts. All coins in an input must be consumed entirely — any excess is sent back as "change" in a separate output. The first transaction in every block is the **coinbase transaction**, which creates new coins as a mining reward and has no inputs. Bitcoin maintains a list of all **Unspent Transaction Outputs (UTXO)** to track available funds.

When two miners solve the puzzle simultaneously, a **fork** occurs. The network resolves this by following the **longest chain rule**: the branch that accumulates the most work (longest chain) is accepted as valid. Transactions in the abandoned (orphan) block are returned to the mempool for inclusion in a future block.

### 3.10 Group Key Security Requirements

There are four key security requirements for group key management:

- **Key secrecy** means that only authorized members of the group receive the group key.
- **Forward secrecy** means that a user who newly joins the group cannot derive any previous group keys.
- **Backward secrecy** means that a user who leaves the group cannot derive any future group keys.
- **Rekeying** means that the group key is changed whenever the group membership changes (join or leave).

### Exam-Ready Checklist — Distributed Systems

- [ ] Write all five Needham-Schroeder messages from memory and explain the stolen session key weakness
- [ ] Use the DH notation correctly: $BK(k) = g^k \pmod p$ and $DH(bk, k) = bk^k \pmod p$
- [ ] Calculate the TGDH group key for any user in a 4-user tree
- [ ] List the LKH keys known by any user, and construct the broadcast message when a user leaves
- [ ] Describe the two types of secret sharing (linear vs threshold) with their reconstruction methods
- [ ] Write Shamir's polynomial and the Lagrange reconstruction formula
- [ ] Write the RSA multi-signature equations for signing, reconstruction, and verification
- [ ] Describe all four e-voting steps with their corresponding formulas
- [ ] Explain the blockchain 6-step operation, Proof of Work, and the UTXO model

**Drill these definitions until you can write them blind. This is the most formula-heavy topic.**

---

## Topic 4: Anonymization & Secure Multiparty Computation (Slide 13)

> **ASKED ON EXAM** — S2019 (10pts), S2020 (10pts), S2021 (10pts), W2022/23 (20pts), W2023/24 (10pts): _5/5 exams, 10-20 points_

### 4.1 Core Definitions

**Privacy** is the right of individuals to protect their personal lives and matters from the outside world and to determine which information about themselves should be known to others.

**Personal data** is any information that relates to an identified or identifiable natural person, such as a name, address, or identification number.

The **GDPR** establishes six principles for processing personal data: lawfulness, fairness, and transparency; purpose limitation; data minimization; accuracy of processed data; storage limitation; and integrity and confidentiality. The principle of **purpose limitation** is particularly important for the exam — it means data can only be used for the purpose for which it was originally collected.

A crucial rule to remember is that **anonymous data is not personal data**, and therefore the GDPR does not apply to it. Once data has been properly anonymized, it falls outside the scope of data protection regulation.

### 4.2 Attribute Types

There are three types of attributes in a dataset:

**Direct identifiers** are attributes that can identify an individual on their own. Examples include a person's name, home address, or identity number.

**Quasi-identifiers** are attributes that cannot identify an individual alone but can do so when combined with other quasi-identifiers. Examples include age, gender, and ZIP code. It is important to note that quasi-identifiers do not **always** uniquely identify a person — they only **can** do so in combination.

**Sensitive attributes** are attributes whose values are considered sensitive and worth protecting. Examples include diseases, salary, and political convictions.

### 4.3 Privacy Threats

There are three types of privacy threats:

**Membership disclosure** occurs when an attacker learns whether a specific individual is represented in a dataset. This threat relies on leaking meta-information. For example, if a dataset is known to contain only cancer patients, simply knowing someone is in the dataset reveals they have cancer.

**Attribute disclosure** occurs when an attacker learns the value of a sensitive attribute for an individual. Importantly, attribute disclosure is possible even without matching the individual to a specific record in the dataset.

**Identity disclosure** occurs when an attacker successfully matches an individual to a specific record in the dataset. This is the most severe threat because it reveals all attribute values associated with that individual.

### 4.4 Attacker Models

> **ASKED ON EXAM** — W2022/23 (13a,13b), W2023/24 (12a): "Define semi-honest adversary / prosecutor / journalist"

The **prosecutor attacker** targets a specific individual and **assumes** that the individual is contained in the dataset. Because the prosecutor already knows the target is present, they focus entirely on linking the target to a specific record.

The **journalist attacker** also targets a specific individual but does **not** know whether the individual is contained in the dataset. The journalist must first determine whether the target is present before attempting to link them to a record.

The **marketer attacker** does not target a specific individual. Instead, the marketer attempts to re-identify a large number of individuals in the dataset. An attack is only considered successful if a significant fraction of individuals is re-identified.

The key difference between the prosecutor and journalist models (asked on W2023/24) is that both target a specific individual, but the prosecutor knows the target is in the dataset while the journalist does not. The marketer differs from both by targeting many individuals rather than one.

In the context of Secure Multiparty Computation, a **semi-honest adversary** follows the protocol correctly — all outputs, computations, and sent messages are exactly as specified by the protocol. However, the semi-honest adversary may use their own knowledge and any received data to infer more information than the protocol intended to reveal. This type of adversary violates mainly privacy constraints, not correctness.

A **malicious adversary** may arbitrarily deviate from the protocol. This means they can send incorrect messages, skip steps, or behave in any way they choose. A malicious adversary can violate both privacy constraints and the correctness of the computation's outcome.

### 4.5 Pseudonymization vs Anonymization

**Pseudonymization** means that personal data can no longer be attributed to a specific individual without the use of additional information, which must be kept separately. However, pseudonymization is **reversible** — with the additional information (such as a decryption key or lookup table), the original identity can be recovered. Because the data is still considered personal data, the **GDPR continues to apply** to pseudonymized data. Examples include replacing names with codes, encrypting data, or hashing values.

**Anonymization** means that the data does not relate to an identified or identifiable natural person. Anonymization is designed to be **irreversible** — the effort required for re-identification is excessively high. Because anonymous data is no longer personal data, the **GDPR does not apply**. Examples include generalization, suppression, and microaggregation.

### 4.6 Anonymization Techniques

Anonymization techniques are grouped into three categories of masking methods:

**Perturbative methods** alter the actual attribute values, which means the new dataset may contain erroneous information. One example is adding noise drawn from a normal distribution (such as changing Age 23 to Age 27 by adding noise of 4). Another perturbative method is **microaggregation**, which replaces a group of values with a summary statistic such as the mean.

**Non-perturbative methods** replace attribute values with less specific (but not incorrect) values. **Generalization (recoding)** makes values broader — for example, replacing an exact age of 23 with the interval [20-25]. There are two forms of generalization: **global recoding** replaces all occurrences of a value with the same generalized value, while **local recoding** allows the same value to be replaced with different generalizations depending on the subset it belongs to. **Suppression** removes data entirely from the table, which reduces utility but can prevent outliers from forcing excessive generalization.

**Synthetic data** replaces attribute values with artificially created values that may be based on a statistical model of the real data.

### 4.7 Microaggregation (Univariate vs Multivariate)

> **ASKED ON EXAM** — W2022/23 (12a): "Explain the difference"

**Univariate microaggregation** applies microaggregation to each attribute independently. Each attribute is processed separately, replacing groups of values with their mean. This approach does **not** ensure k-anonymity because the grouping is done per attribute, not across all attributes simultaneously.

**Multivariate microaggregation** applies microaggregation to all attributes at once. Records are clustered based on all their attribute values, and each cluster's values are replaced by the cluster's centroid. This approach **ensures k-anonymity** for the dataset, provided all quasi-identifier attributes are included in the process.

### 4.8 k-Anonymity

> **ASKED ON EXAM** — W2022/23 (12b): "Define k-anonymity"

A release of data is said to have the **k-anonymity** property if every occurring combination of values of quasi-identifiers appears for at least k individuals in the dataset. The groups of individuals sharing the same quasi-identifier values are called **equivalence classes**. The value of k must be greater than 1.

k-Anonymity is vulnerable to two attacks:

The **unsorted matching attack** exploits the fact that entries in a published dataset may maintain their original order. If an attacker has access to two different k-anonymous publications of the same data, they can link records based on their positions, potentially breaking k-anonymity. The fix is to shuffle (permute) the entries before publishing.

The **complementary release attack** occurs when multiple k-anonymous versions of the same data are published using different generalization strategies. By combining information from different publications, an attacker can narrow down the possible values and break k-anonymity. The fix is to treat all attributes as quasi-identifiers or base all subsequent publications on the first one.

### 4.9 l-Diversity

> **ASKED ON EXAM** — W2023/24 (12b): "Define distinct l-diversity"

An equivalence class is said to fulfill **l-diversity** if at least $l$ "well-represented" values for the sensitive attribute occur within it. A table meets the l-diversity requirement if all of its equivalence classes are l-diverse. The value of $l$ must be greater than 1.

There are three interpretations of "well-represented":

**Distinct l-diversity** requires that there are at least $l$ different values for the sensitive attribute in each equivalence class. This is the simplest interpretation.

**Entropy l-diversity** requires that the entropy of each equivalence class satisfies $\text{Entropy}(E) \ge \log(l)$, where $\text{Entropy}(E) = -\sum p(E,s) \cdot \log(p(E,s))$ and $p(E,s)$ is the fraction of records in $E$ with sensitive attribute value $s$.

**Recursive (c,l)-diversity** requires that the most frequent sensitive value does not appear too often relative to the less frequent values. Specifically, $r_1 < c \cdot (r_l + r_{l+1} + \dots + r_m)$, where $r_i$ is the count of the $i$-th most frequent value in the equivalence class.

### 4.10 t-Closeness

An equivalence class is said to fulfill **t-closeness** if the distribution of sensitive attribute values within that class differs from the distribution in the overall table by at most $t$. A table meets the t-closeness requirement if all of its equivalence classes are t-close.

### 4.11 Oblivious Transfer (OT 1/2)

> **ASKED ON EXAM** — W2022/23 (13c): "Which goals should be reached by an oblivious transfer?"

An oblivious transfer protocol must achieve four goals:

1. Alice holds two secret messages $M_0$ and $M_1$.
2. Bob receives exactly one of the two messages — specifically $M_b$, where $b$ is Bob's choice of either 0 or 1.
3. Alice does not learn which message Bob chose to receive.
4. Bob learns nothing about the message he did not choose.

### 4.12 Garbled Circuits (GC)

Garbled circuits allow two parties — Alice (the Garbler) and Bob (the Evaluator) — to jointly compute a function on their secret inputs without revealing those inputs to each other. The function is modeled as a boolean circuit consisting of gates connected by wires. Both parties know the circuit structure, but each keeps their input secret.

**The setup process has six steps:**

1. Alice constructs the function as a boolean circuit made up of logic gates and wires.
2. Alice constructs the truth table for each gate in the circuit.
3. Alice generates a random label for each possible state (0 or 1) at each wire. Because the labels are random, they do not reveal the actual bit values.
4. Alice encrypts each output-wire label using the corresponding pair of input-wire labels as the encryption key (double encryption).
5. Alice garbles (randomly shuffles) the rows of each encrypted truth table so that the row order does not reveal information.
6. Alice sends the garbled circuit and her own input labels to Bob.

**The evaluation process works as follows:**

1. Bob receives Alice's input label, but since labels are randomly generated, he cannot determine Alice's actual input bit.
2. Bob obtains the label for his own input through **oblivious transfer**. This ensures that Alice does not learn which input Bob chose.
3. Bob attempts to decrypt each row of the garbled table using his two input labels until he finds the one that decrypts correctly, giving him the output label.
4. The output label either feeds into the next gate as input or serves as the final output of the circuit.
5. Bob sends the final output label to Alice, who knows the mapping between labels and real values. Alice then shares the result with Bob.

### 4.13 GC Performance Optimizations

| Technique           | Rows per gate (AND/XOR/NOT) | Key advantage                                                     |
| ------------------- | --------------------------- | ----------------------------------------------------------------- |
| **Classical**       | 4 / 4 / 2                   | This is the baseline with no optimizations.                       |
| **Point & Permute** | 4 / 4 / 2                   | Bob always finds the correct row in exactly 1 decryption attempt. |
| **GRR3**            | **3** / 3 / 1               | The transmitted table is reduced by 1 row per gate.               |
| **Free-XOR**        | 4 / **0** / 0               | XOR and NOT gates require no encryption at all.                   |
| **GRR3 + Free-XOR** | **3** / **0** / 0           | This is the best combined optimization.                           |

> **ASKED ON EXAM** — W2023/24 (12c): "Describe advantage of point-and-permute"

**Point & Permute** solves the problem that in the classical approach, Bob may need up to 4 decryption attempts to find the correct row. In Point & Permute, each label is augmented with a random **sorting bit**. The table is sorted by these bits instead of being randomly shuffled. Because Bob knows the sorting bits of his input labels, he can immediately identify the correct row and decrypt it in exactly one attempt. There is no security loss because the sorting bit is chosen randomly and is independent of the actual input value.

> **ASKED ON EXAM** — W2022/23 (13d): "Describe advantage of GRR3 and how it is reached"

**GRR3 (Garbled Row Reduction 3)** builds on Point & Permute. Because the table is sorted by the sorting bits, the top row of the garbled table is always predictable. Alice chooses the output label for the top row such that the encrypted value is a zero-bitstring of length N. Since the top row is known to be all zeros, it does not need to be transmitted to Bob. This reduces the size of each garbled table from 4 rows to **3 rows**, saving bandwidth. Note that GRR3 reduces the number of **rows**, not the number of gates.

### 4.14 Exam T/F Compilation (VERY common question type)

> **ASKED ON EXAM** — S2019, S2020, S2021 (Privacy T/F blocks), W2022/23 (12d, 6 statements), W2023/24 (12d)

| Statement                                                                                                       | Answer | Explanation                                                                                                             |
| --------------------------------------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------- |
| The GDPR demands that anonymous data is protected from being used for different purposes.                       | **F**  | The GDPR does not apply to anonymous data at all.                                                                       |
| Pseudonymization always makes it impossible to link an individual to certain data.                              | **F**  | Pseudonymization is reversible with additional information.                                                             |
| A release has k-anonymity if each person's info cannot be distinguished from at least k-1 others.               | **T**  | This is the definition of k-anonymity.                                                                                  |
| GDPR stands for "guide of data protection and privacy respectation."                                            | **F**  | GDPR stands for General Data Protection Regulation.                                                                     |
| Global recoding replaces values with summary statistics.                                                        | **F**  | Global recoding uses generalization hierarchies, not summary statistics. That describes microaggregation.               |
| In local recoding, a given value might be replaced with different values.                                       | **T**  | Different subsets may apply different generalizations to the same original value.                                       |
| Pseudonymization should be preferred over anonymization in all use cases.                                       | **F**  | The choice depends on the specific use case and requirements.                                                           |
| In multivariate microaggregation, each value is made indistinguishable from k-1 values of different attributes. | **F**  | Values are made indistinguishable from values of the same attribute across different records, not different attributes. |
| The anonymization technique "suppression" always preserves the highest possible utility.                        | **F**  | Suppression removes data entirely, which reduces the utility of the dataset.                                            |
| Considering the GDPR, data is not subject to a purpose limitation.                                              | **F**  | Purpose limitation is one of the six core GDPR principles.                                                              |
| Encryption is an anonymization technique.                                                                       | **F**  | Encryption is a form of pseudonymization because it is reversible with the decryption key.                              |
| Quasi-identifiers always allow to uniquely identify a natural person.                                           | **F**  | Quasi-identifiers can potentially identify someone when combined, but they do not always do so.                         |
| Hashing a dataset twice turns it anonymous.                                                                     | **F**  | Hashing is still a form of pseudonymization. It can be reversed through lookup tables or brute force.                   |
| In GRR3, the number of gates is reduced from 4 to 3.                                                            | **F**  | It is the number of **rows per gate** that is reduced from 4 to 3, not the number of gates.                             |

### Exam-Ready Checklist — Anonymization & SMPC

- [ ] Define k-anonymity, distinct l-diversity, and t-closeness in complete sentences
- [ ] Describe all five attacker models: prosecutor, journalist, marketer, semi-honest, and malicious
- [ ] Explain the difference between pseudonymization and anonymization, including GDPR implications
- [ ] Explain the difference between univariate and multivariate microaggregation
- [ ] Explain the difference between global and local recoding
- [ ] State the four goals of oblivious transfer
- [ ] Describe the six setup steps and the evaluation process for garbled circuits
- [ ] Explain the advantage of Point & Permute and why there is no security loss
- [ ] Explain the advantage of GRR3 and how it is achieved
- [ ] Review the T/F table above — these statements recur across exams

**Drill these definitions until you can write them blind.**

---

## Phase 1 Active Recall Quiz

**Q1 (Side Channels, 3 pts):** Describe the difference between side channels and covert channels.

**Answer:** A side channel is an unintentional information leakage that occurs through physical observables during a system's normal operation. A covert channel is an intentional communication channel that an attacker deliberately establishes by encoding data into observable system behavior. The key difference is that side channels are unintentional while covert channels are deliberately created.

**Q2 (Side Channels, 5 pts):** What side channel enables the padding oracle attack? Which information is leaked? What does the attacker ultimately obtain?

**Answer:** The side channel is the server's error response, which differs between invalid padding and invalid content. The information leaked is whether the PKCS#7 padding of the decrypted ciphertext is valid, which amounts to 1 bit of information per query. By systematically modifying ciphertext bytes and observing the oracle's responses, the attacker can recover the entire plaintext byte by byte without knowing the encryption key. Interesting targets include any system using CBC mode encryption that returns distinguishable padding errors.

**Q3 (Threat Intel, 6 pts):** Name the main motivation for each Threat Actor type.

**Answer:** Nation states are motivated by geopolitical advantage and espionage. Cyber criminals are motivated by financial gain. Hacktivists are motivated by ideological or political agendas. Cyber terrorists are motivated by causing fear and disruption for political goals. Thrill seekers are motivated by curiosity and reputation. Insider threats are motivated by revenge, financial gain, or coercion.

**Q4 (Distributed Systems, 4 pts):** Given the standard 4-user TGDH key tree, write the group key calculation of user u1.

**Answer:** User $u_1$ knows their own secret key $k_{2,0}$ and the blind keys $bk_{2,1}$ and $bk_{1,1}$. In the first step, $u_1$ computes $k_{1,0} = DH(bk_{2,1}, k_{2,0}) = bk_{2,1}^{k_{2,0}} \pmod p$. In the second step, $u_1$ computes the group key $k_{0,0} = DH(bk_{1,1}, k_{1,0}) = bk_{1,1}^{k_{1,0}} \pmod p$.

**Q5 (Anonymization, 2+2 pts):** Define the semi-honest adversary. Define the prosecutor attacker model.

**Answer:** A semi-honest adversary follows the protocol correctly — all outputs, computations, and messages are exactly as specified. However, it may use its own knowledge and received data to infer more information than the protocol intended to reveal. It violates mainly privacy constraints, not correctness. The prosecutor attacker targets a specific individual and assumes that the individual is contained in the dataset. Unlike the journalist attacker, the prosecutor has background knowledge confirming the target's presence.

**Bonus Q6 (T/F):**

1. Encryption is an anonymization technique. → **F** — Encryption is pseudonymization because it is reversible with the decryption key.
2. In the t-test, we assume both groups are approximately normally distributed. → **T**
3. The advantage of side channels over brute force is that they reduce the key space to search. → **T** — Side channels reduce complexity from exponential (key space) to linear (key length).
4. In GRR3, the number of gates is reduced from 4 to 3. → **F** — The number of rows per gate is reduced, not the number of gates.
5. Forward secrecy means a new user joining cannot derive old group keys. → **T**
