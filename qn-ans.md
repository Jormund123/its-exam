# All Past Exam Questions & Model Answers

This document contains ALL unique exam questions from ALL past exams, organized by topic, answered non-redundantly. Where the same or similar question appeared on multiple exams, all exam references are noted but the answer is given only once.

**Exam Key:**

- **S2019** = Summer 2019 (exam-2.txt), 11 tasks, 120 pts
- **S2020** = Summer 2020 (exam-3.txt), 10 tasks, 100 pts
- **S2021** = Summer 2021 (exam-1.txt), 12 tasks, 120 pts
- **W2022/23** = Winter 2022/23 (exam-7.txt), 15 tasks, 150 pts — transitional exam
- **W2023/24** = Winter 2023/24 (exam-9.txt), 12 tasks, 120 pts — most recent
- **Online Test** = Performance Test 1 (exam-4.txt), ~20 pts, MCQ/practical

---

## Topic 1: Side Channel Attacks (5/5 exams)

### Q1.1: "Describe the difference between side channels and covert channels." [S2021 Task 3a (3pts), W2023/24 Ex.1a (3pts)]

**A:** A side channel is an unintentional information leakage that occurs through physical observables (such as timing, power consumption, or electromagnetic emissions) during a system's normal operation. The system designer never intended for this channel to exist, and an attacker passively observes these leakages to extract secret information.

A covert channel is an intentional communication channel that an attacker deliberately establishes by encoding information into a system's observable behavior. Unlike a side channel, the attacker actively creates this channel to exfiltrate data. For example, malware could encode stolen data in the timing patterns of DNS queries.

The key distinction is intent: side channels are unintentional and exploited by the attacker, while covert channels are intentionally established by the attacker.

---

### Q1.2: "List at least two reasons why information leakage in side channels is exploitable." [S2019 Task 1a (2pts)]

**A:** Side channels are exploitable for at least three reasons:

1. **Data-dependent computation:** Different secret inputs cause the system to behave differently in terms of physical characteristics such as timing or power draw.
2. **Shared resources:** The attacker and victim share hardware resources like the CPU cache or memory bus, which allows the attacker to observe the victim's behavior indirectly.
3. **Observable physical effects:** Physical properties like timing, power consumption, and electromagnetic emissions can be measured from outside the system without the system being aware.

---

### Q1.3: "List at least two types of side channels that we can observe when treating the system as a black box." / "Are these attacks typically passive or active?" [S2020 Task 2a (3pts), S2020 Task 2b (2pts)]

**A:** When treating the system as a black box (observing only external behavior without knowledge of internals), we can observe:

1. **Timing side channels:** Differences in how long the system takes to respond to different inputs.
2. **Power consumption side channels:** Variations in the amount of electrical power the system draws during operation.
3. **Electromagnetic emission side channels:** EM radiation emitted by electronic components during computation.
4. **Acoustic side channels:** Sounds produced by hardware components such as coil whine.
5. **Error message side channels:** Observable differences in server responses (e.g., different error messages for different failure types).

These attacks are typically **passive**. The attacker does not need to modify the system or inject anything into it. They only observe the physical emanations or behavioral differences that the system produces during its normal operation.

---

### Q1.4: "Compared to brute forcing a cryptographic algorithm, what advantage do side channels provide?" [S2020 Task 2b context, S2021 Task 3b (2pts), W2022/23 Task 4b (3pts)]

**A:** The complexity of brute-forcing a cryptographic algorithm depends on the key space, which grows exponentially with key length. For an n-bit key, brute force requires searching through up to 2^n possible keys.

In contrast, the complexity of a side channel attack depends on the key length itself, which grows only linearly. An attacker needs roughly n observations to recover an n-bit key, one observation per bit.

Side channels therefore reduce the problem from searching an exponential key space to making a linear number of observations, which is a dramatic advantage that makes otherwise secure algorithms vulnerable.

---

### Q1.5: "What side channel enables the padding oracle attack? / Which information is leaked? / What information does the attacker ultimately obtain? / What could be interesting targets?" [S2019 Task 1b (5pts), S2020 Task 2c (5pts), S2021 Task 3c (5pts), W2023/24 Ex.1b (7pts)]

**A:** The padding oracle attack relies on three elements:

1. **CBC mode encryption:** In CBC mode, each plaintext block is XORed with the previous ciphertext block before encryption. During decryption: $P_i = D_k(C_i) \oplus C_{i-1}$.
2. **PKCS#7 padding:** The last block of plaintext is padded so that the last byte indicates the padding length. Valid padding looks like: `01`, or `02 02`, or `03 03 03`, and so on.
3. **Error oracle (the side channel):** The server responds differently to invalid padding versus invalid content. This difference in behavior is the side channel.

**What information is leaked:** The server reveals whether the PKCS#7 padding of the decrypted ciphertext is valid or not. This amounts to 1 bit of information per query.

**How the attack works:** The attacker targets the last byte of a plaintext block $P_i$. They systematically modify the last byte of the preceding ciphertext block $C_{i-1}$, trying all 256 possible values. For each modified value, they send the pair $(C_{i-1}', C_i)$ to the server. When the server reports "valid padding," the attacker knows the last byte of $P_i'$ equals `0x01`. From this, the attacker computes $D_k(C_i)[\text{last}] = C_{i-1}'[\text{last}] \oplus \text{0x01}$, and then recovers $P_i[\text{last}] = D_k(C_i)[\text{last}] \oplus C_{i-1}[\text{last}]$. The attacker repeats for each byte position, eventually recovering the entire plaintext block, and then repeats for all blocks.

**What the attacker ultimately obtains:** The entire plaintext is recovered byte by byte, without ever knowing the encryption key. At most 256 attempts per byte are needed.

**Interesting targets:** Any system that uses CBC mode encryption and returns distinguishable errors for bad padding versus bad content, including web applications, TLS implementations, and APIs.

---

### Q1.6: "Does any of the reasons you listed in (a) apply to (b)? Explain your answer." [S2019 Task 1c (3pts)]

**A:** Yes, the reason of "data-dependent computation" applies directly to the padding oracle attack. The server's decryption routine processes the padding bytes and produces different error responses (bad padding vs. bad content) depending on the specific values in the ciphertext. This data-dependent behavior — where different inputs produce observably different outputs — is exactly what makes the side channel exploitable. The reason of "observable physical effects" also applies, since the different error responses are observable by the attacker over the network.

---

### Q1.7: "In the Rowhammer attack, an attacker flips a bit at some memory address, without the computer noticing. Give two examples where flipping a single bit compromises the security of the system and describe how the security is compromised." [W2022/23 Task 4a (4pts)]

**A:** Rowhammer is a hardware vulnerability in DRAM where repeatedly accessing specific memory rows at high speed causes electrical interference that flips bits in physically adjacent rows, without the system detecting it.

**Example 1 — Page table entry bit flip:** The attacker flips a permission bit in a page table entry, changing a read-only page to read-write. This gives the attacker write access to protected memory such as kernel memory, leading to privilege escalation.

**Example 2 — Authentication flag bit flip:** The attacker flips a bit in an "is_admin" or "authenticated" flag stored in memory. This can bypass authentication checks and grant unauthorized access to the attacker.

---

### Q1.8: "Why does measuring power consumption of a CPU leak information? Give two examples where measuring the power consumption leaks information." [W2022/23 Task 4c (3pts)]

**A:** Measuring power consumption leaks information because different CPU instructions consume different amounts of power. When the CPU performs data-dependent operations like conditional branches or multiplications, these operations create measurable power signatures that correlate with the secret data being processed.

**Example 1:** In RSA's square-and-multiply algorithm, multiply operations consume noticeably more power than square-only operations. An attacker can look at a single power trace and directly determine which key bits are 1 (square + multiply) versus 0 (square only). This is Simple Power Analysis (SPA).

**Example 2:** In AES, the power consumption during S-box table lookups correlates with the Hamming weight of the processed data. By collecting many power traces and performing statistical analysis (Differential Power Analysis / DPA), the attacker can determine which key bytes are being used.

---

### Q1.9 (Online Test): "When computing RSA digital signatures, modular exponentiation needs to be performed. Which method is used in a straightforward implementation?" [Online Test Q6 (1pt)]

**A:** Square and Multiply.

---

### Q1.10 (Online Test): "Which side channel attacks can be used for the above method [square-and-multiply]?" [Online Test Q7 (2pts)]

**A:** Timing attack, Power analysis, and Cache timing. These are all applicable because the square-and-multiply algorithm has data-dependent branches (multiply only executes when a key bit is 1), which causes observable differences in execution time, power consumption, and cache access patterns.

---

## Topic 2: Supply Chain & Threat Intelligence (5/5 exams)

### Q2.1: "Name the key concepts of information security and define each in one sentence." [W2022/23 Task 10a (3pts), W2023/24 Ex.10a (3pts), Online Test Q8 (1pt)]

**A:** The three key concepts of information security are:

- **Confidentiality** means that information is accessible only to those who are authorized to access it.
- **Integrity** means that information has not been modified by unauthorized parties and remains accurate and complete.
- **Availability** means that information and systems are accessible to authorized users whenever they are needed.

---

### Q2.2: "Name the main motivation for each Threat Actor type." / "Name and map the main motivation for three Threat Actor types." [S2021 Task 4b (6pts), W2022/23 Task 10b (3pts)]

**A:** There are six main types of threat actors, each driven by a different primary motivation:

- **Nation states** are motivated by geopolitical advantage and espionage. They conduct cyber operations to further national interests.
- **Cyber criminals** are motivated by financial gain. They steal data, deploy ransomware, or commit fraud for profit.
- **Hacktivists** are motivated by ideological or political agendas. They use cyberattacks to promote a social or political cause (e.g., defacing a website).
- **Cyber terrorists** are motivated by causing fear and disruption for political goals. They aim to create terror through attacks on critical infrastructure.
- **Thrill seekers (script kiddies)** are motivated by personal satisfaction, curiosity, or reputation. They attack systems for the challenge or bragging rights.
- **Insider threats** are motivated by revenge, financial gain, or coercion. They exploit their legitimate access to cause harm from within an organization.

---

### Q2.3: "To which threat actor does the following statement fit best: 'Is driven by believe and willing to spend an enormous amount of resources'?" [S2019 Task 9a (1pt)]

**A:** This best fits a **Cyber Terrorist**. They are driven by belief (ideology/political conviction) and willing to spend enormous resources to achieve their goals of creating fear and disruption.

---

### Q2.4 (Online Test): "Which Threat Actor is primarily motivated by financial gain?" [Online Test Q9 (1pt)]

**A:** Cybercriminal.

---

### Q2.5 (Online Test): "Which Threat Actor would most probably deface a website?" [Online Test Q10 (1pt)]

**A:** Hacktivist. Website defacement is a common tactic for promoting ideological or political messages.

---

### Q2.6: "What is the Intrusion Kill Chain used for? Name and explain one stage." / "To which step of the Intrusion Kill Chain does footprinting belong? Explain that step." / "Explain one step (of your choice) of the Intrusion Kill Chain. Name the step before and after." [S2020 Task 3a (3pts), W2022/23 Task 10c (3pts), W2023/24 Ex.10b (2pts)]

**A:** The Intrusion Kill Chain is a model that describes the seven sequential phases of a cyberattack. It is used to understand, detect, and disrupt attacks at each phase. The seven phases are:

1. **Reconnaissance:** The attacker gathers information about the target using techniques like OSINT and footprinting. (Footprinting belongs to this step.)
2. **Weaponization:** The attacker creates an attack payload by combining an exploit with a backdoor (e.g., packaging malware inside a PDF). Preceded by Reconnaissance, followed by Delivery.
3. **Delivery:** The attacker transmits the payload to the target through a channel such as a phishing email, USB drive, or compromised website. Preceded by Weaponization, followed by Exploitation.
4. **Exploitation:** The payload is triggered on the target system, e.g., when the victim opens a malicious file. Preceded by Delivery, followed by Installation.
5. **Installation:** The attacker installs a persistent backdoor on the compromised system. Preceded by Exploitation, followed by Command & Control.
6. **Command & Control (C2):** The attacker establishes a communication channel from the compromised system back to their infrastructure, allowing remote control. Preceded by Installation, followed by Actions on Objectives.
7. **Actions on Objectives:** The attacker achieves their goal (exfiltrating data, disrupting operations, lateral movement). Preceded by Command & Control.

---

### Q2.7: "What characteristics of Indicators of Compromise are visualized by the 'Pyramid of Pain'?" [S2020 Task 3b (2pts), S2021 Task 4a (2pts)]

**A:** The Pyramid of Pain visualizes how much difficulty ("pain") it causes an attacker when a defender detects and blocks each type of Indicator of Compromise. The pyramid orders IoC types by how costly they are for the attacker to change, from trivially changeable at the bottom to extremely difficult at the top.

---

### Q2.8: "Order the following parts of the pyramid of pain in ascending order of difficulty to extract by the defender: IP Addresses, Artifacts, Hash values, TTP, Tools, Domains." [S2019 Task 9b (6pts)]

**A:** From easiest to change (bottom) to hardest to change (top):

1. **Hash Values** — trivially changed by recompiling malware
2. **IP Addresses** — easy to change by switching servers
3. **Domain Names** — somewhat annoying, must register new domains
4. **Network/Host Artifacts** — frustrating, requires modifying malware behavior
5. **Tools** — challenging, must rewrite or replace custom tools
6. **TTPs (Tactics, Techniques, Procedures)** — hardest, represents fundamental behavioral patterns

---

### Q2.9: "What is so special about Insider Threats?" [S2020 Task 3c (2pts)]

**A:** Insider threats are special because the attacker already has legitimate, authorized access to the organization's systems, networks, and data. This means they can bypass many external security controls (firewalls, access controls) that would stop other threat actors. They have firsthand knowledge of the organization's vulnerabilities, processes, and valuable assets. Detecting insider threats is particularly difficult because their activities may appear indistinguishable from their normal work duties.

---

### Q2.10: "What is the idea behind Supply Chain Attacks?" / "Explain the principle of a supply chain attack." [S2019 Task 9c (2pts), S2020 Task 3d (3pts), S2021 Task 4c (2pts), W2023/24 Ex.10c (2pts)]

**A:** A supply chain attack occurs when an attacker compromises a trusted component in the software supply chain — such as a library, build tool, update mechanism, or code repository — in order to distribute malicious code to downstream consumers who trust that source. The attack is effective because victims have no reason to suspect the compromised component, since it comes from a legitimate and previously trusted source.

Common techniques include typosquatting (registering package names similar to popular ones, e.g., "crossenv" vs. "cross-env"), watering hole attacks (compromising frequently visited websites), dependency confusion (uploading a malicious public package with the same name as an internal one), and compromised build pipelines.

A real-world example is the event-stream incident of 2018, where an attacker gained maintainer access to a popular npm package and added a malicious dependency targeting a Bitcoin wallet application.

---

### Q2.11: "What are APTs and what characterizes them?" / "Can different APT campaigns be strictly separated?" [W2023/24 Ex.10d (3pts), S2019 Task 9d (1pt)]

**A:** An APT (Advanced Persistent Threat) is a type of cyberattack characterized by three properties:

- **Advanced** means the attacker uses sophisticated tools, techniques, and procedures (TTPs), often including custom malware and zero-day exploits.
- **Persistent** means the attacker maintains access to the target for long periods (months or years), using a low-and-slow approach to avoid detection.
- **Threat** means the attacker is well-funded and organized, with specific strategic objectives, typically operating at nation-state level resources.

APTs are further characterized by strategic patience, targeting of specific high-value targets, use of multiple attack vectors, and the ability to adapt their techniques when discovered.

**Can different APT campaigns be strictly separated?** No. Different APT campaigns cannot be strictly separated because APT groups may share tools, infrastructure, and techniques, making attribution and separation difficult.

---

### Q2.12: "What is footprinting?" / "Is scanning the target's public server for open ports a suitable technique for footprinting? Give a reason." [S2020 Task 3a context, W2022/23 Task 10d (1pt), Online Test Q12 (1pt)]

**A:** Footprinting is a reconnaissance technique that uses only external or third-party sources to gather information about a target. The defining characteristic is that there is no direct interaction with the target system. Examples include WHOIS lookups, public DNS queries, reviewing social media profiles, reading job postings, and consulting public records.

**Is scanning the target's public server for open ports footprinting?** No. Port scanning involves sending packets directly to the target, which constitutes active reconnaissance and direct interaction. Footprinting is strictly passive and relies only on publicly available information gathered without touching the target.

**Online Test answer:** Footprinting is "Obtaining information about a target through third-party sources."

---

### Q2.13 (Online Test): "To which type of Threat Intelligence do Indicators of Compromise belong?" [Online Test Q11 (1pt)]

**A:** Operational Threat Intelligence. Indicators of Compromise are actionable, technical data points (like IP addresses, file hashes, domain names) used to detect and respond to threats in real time.

---

## Topic 3: Distributed Systems — Secret Sharing, Key Management, E-Voting, Blockchain (5/5 exams)

### Q3.1: "Write down the keys known by user u1 / u3 / u4 (LKH protocol)." [S2019 Task 4a (2pts), S2020 Task 5a (2pts), S2021 Task 5a (2pts)]

**A:** In the LKH (Logical Key Hierarchy) protocol, each user knows all keys on the path from their leaf node to the root.

For the standard 4-user tree:

```
              k_{0,0}   (group key / root)
             /        \
        k_{1,0}      k_{1,1}
        /    \       /     \
    k_{2,0} k_{2,1} k_{2,2} k_{2,3}
      u1      u2     u3      u4
```

- **User u1** knows: $k_{2,0}$ (own leaf key), $k_{1,0}$ (parent), $k_{0,0}$ (group key).
- **User u3** knows: $k_{2,2}$ (own leaf key), $k_{1,1}$ (parent), $k_{0,0}$ (group key).
- **User u4** knows: $k_{2,3}$ (own leaf key), $k_{1,1}$ (parent), $k_{0,0}$ (group key).

---

### Q3.2: "User u_j joins the group and is added at the position of user u_i. Draw the modified tree." [S2019 Task 4b (4pts), S2020 Task 5b (3pts), S2021 Task 5b (2pts)]

**A:** When a new user joins at the position of an existing user, the existing user's leaf node is split: the existing node moves down one level to become the left child of a new internal node, and the joining user becomes the right child.

For example (S2020/S2021: u5 joins at u3's position, k*{2,2} moves to k*{3,4}):

```
                  k_{0,0}
                 /        \
            k_{1,0}      k_{1,1}
            /    \       /     \
        k_{2,0} k_{2,1} k_{2,2}  k_{2,3}
          u1      u2    /    \      u4
                    k_{3,4} k_{3,5}
                      u3      u5
```

The tree gains a new level under the position where the join occurs. All keys on the path from the new node to the root must be updated.

---

### Q3.3: "A group controller uses the LKH protocol (group oriented) for the key update. Specify the broadcast message that enables all members to calculate the new group key." [S2019 Task 4c (4pts), S2020 Task 5c (2pts), S2021 Task 5c (3pts)]

**A:** When a user leaves, all keys on the path from the leaving user's leaf to the root must be replaced. The GC generates fresh keys and broadcasts them encrypted with keys that only the remaining members possess.

**Example (S2021): $u_2$ leaves from the modified tree (after $u_5$ joined).** The keys that must change are $k_{2,1}$ ($u_2$'s leaf), $k_{1,0}$ (parent), and $k_{0,0}$ (root). The GC generates new keys $\tilde{k}_{1,0}$ and $\tilde{k}_{0,0}$ and broadcasts:

$$
\{ E(\tilde{k}_{1,0}, k_{2,0}), \quad E(\tilde{k}_{0,0}, \tilde{k}_{1,0}), \quad E(\tilde{k}_{0,0}, k_{1,1}) \}
$$

- User $u_1$ decrypts $\tilde{k}_{1,0}$ using $k_{2,0}$, then decrypts $\tilde{k}_{0,0}$ using $\tilde{k}_{1,0}$.
- Users $u_3$, $u_5$, $u_4$ decrypt $\tilde{k}_{0,0}$ using $k_{1,1}$ (which has not changed).
- The departed $u_2$ cannot obtain any new key because they do not possess $k_{2,0}$ or $k_{1,1}$.

The general principle: for each changed key on the path, encrypt the new key with a child key that the leaving user does not possess.

---

### Q3.4: "Now the TGDH protocol and the tree in the figure is used. Write down the keys known by user u1 / u4." [S2020 Task 5d (3pts), S2021 Task 5d (3pts)]

**A:** In TGDH, each user knows their own secret key and the blind keys (BK) of all other tree nodes. They do NOT know other users' secret keys or any internal node's secret key directly — they must compute internal keys using the DH function.

For the standard 4-user tree:

```
              k_{0,0}   (group key)
             /        \
        k_{1,0}      k_{1,1}
        /    \       /     \
    k_{2,0} k_{2,1} k_{2,2} k_{2,3}
      u1      u2     u3      u4
```

**User $u_1$ knows:**

- Own secret key: $k_{2,0}$
- Blind keys of all other nodes: $bk_{2,1}$, $bk_{1,1}$ (and $bk_{2,2}$, $bk_{2,3}$)

**User $u_1$'s group key calculation:**

1. $k_{1,0} = \text{DH}(bk_{2,1}, k_{2,0}) = bk_{2,1}^{k_{2,0}} \pmod p$
2. $k_{0,0} = \text{DH}(bk_{1,1}, k_{1,0}) = bk_{1,1}^{k_{1,0}} \pmod p$

**User $u_4$ knows:**

- Own secret key: $k_{2,3}$
- Blind keys of all other nodes: $bk_{2,2}$, $bk_{1,0}$

**User $u_4$'s group key calculation:**

1. $k_{1,1} = \text{DH}(bk_{2,2}, k_{2,3}) = bk_{2,2}^{k_{2,3}} \pmod p$
2. $k_{0,0} = \text{DH}(bk_{1,0}, k_{1,1}) = bk_{1,0}^{k_{1,1}} \pmod p$

---

### Q3.5: "Write down the TGDH group key calculation of user u1. For comparison, write down the group key calculation if the ITW protocol is used. How many messages are exchanged by TGDH and ITW if user u5 joins?" [W2022/23 Task 7 (4+4+2 pts)]

**A:**

**TGDH group key calculation for $u_1$ (4-user tree):**

1. $k_{1,0} = \text{DH}(bk_{2,1}, k_{2,0}) = bk_{2,1}^{k_{2,0}} \pmod p$
2. $k_{0,0} = \text{DH}(bk_{1,1}, k_{1,0}) = bk_{1,1}^{k_{1,0}} \pmod p$

**ITW (Ingemarsson-Tang-Wong) group key calculation for $u_1$ in a group of 4 users:**
In ITW, all users are arranged in a ring and perform $n-1$ rounds of DH key exchange. Each user generates a secret key $k_i$. In each round, every user applies DH with their own key to the value received from the previous round and passes the result to the next user. After $n-1$ rounds, all users arrive at the same group key.

For 4 users ($u_1$, $u_2$, $u_3$, $u_4$):

- Round 1: $u_1$ computes $bk_1 = g^{k_1} \pmod p$ and sends to $u_2$
- Round 2: $u_1$ receives $g^{k_4}$ from $u_4$, computes $g^{k_4 \cdot k_1} \pmod p$, sends to $u_2$
- Round 3: $u_1$ receives $g^{k_3 \cdot k_4}$ from $u_4$, computes $g^{k_3 \cdot k_4 \cdot k_1} \pmod p$, sends to $u_2$
- Group key for $u_1$: received value $g^{k_2 \cdot k_3 \cdot k_4}$ raised to $k_1 = g^{k_1 \cdot k_2 \cdot k_3 \cdot k_4} \pmod p$

**Messages exchanged when u5 joins:**

- TGDH: The sponsor broadcasts updated blind keys. The number of messages is O(log n) — specifically, the sponsor sends one broadcast message containing the updated blind keys along the path from the insertion point to the root.
- ITW: All n users must perform n-1 rounds, each round involving n messages. For 5 users, that is 4 rounds x 5 messages = 20 messages. ITW requires significantly more communication than TGDH for group membership changes.

---

### Q3.6: "Write down the Needham-Schroeder protocol." / "Explain the weakness of the protocol in case of a stolen session key." [W2022/23 Task 6 (6+4 pts)]

**A:** The Needham-Schroeder protocol establishes a pairwise session key between two users through a trusted Group Controller (GC). User $u_1$ shares key $k_{1,GC}$ with the GC; user $u_2$ shares key $k_{2,GC}$ with the GC.

The five messages are:

$$
\begin{align*}
1.&\quad u_1 \rightarrow GC: ID_1, ID_2, n_1 \\
2.&\quad GC \rightarrow u_1: E(\{n_1, k_{12}, ID_2, E(\{k_{12}, ID_1\}, k_{2,GC})\}, k_{1,GC}) \\
3.&\quad u_1 \rightarrow u_2: E(\tilde{n}_1, k_{12}), E(\{k_{12}, ID_1\}, k_{2,GC}) \quad \text{[ticket]} \\
4.&\quad u_2 \rightarrow u_1: E(\{\tilde{n}_1 - 1, n_2\}, k_{12}) \\
5.&\quad u_1 \rightarrow u_2: E(\{n_2 - 1\}, k_{12})
\end{align*}
$$

Message 2 contains a ticket — $E(\{k_{12}, ID_1\}, k_{2,GC})$ — encrypted with $u_2$'s key, which $u_1$ cannot read. In message 3, $u_1$ forwards this ticket to $u_2$. Messages 4 and 5 provide mutual authentication.

**Weakness with stolen session key:** If the session key k12 is stolen by an attacker, the attacker can replay message 3 to u2 at any later time. Since the ticket does not contain a timestamp, u2 cannot distinguish this replayed message from a fresh session. The attacker can then complete the handshake (messages 4 and 5) using the stolen key. The Kerberos protocol fixes this by adding timestamps.

---

### Q3.7: "Write down different types of secret sharing and describe their main two features." [S2021 Task 6a (3pts), W2023/24 Ex.6a (2pts)]

**A:** There are two main types of secret sharing:

**Linear (additive) secret sharing ($n$-out-of-$n$):** The secret $s$ is split into $n$ shares such that $s = s_1 + s_2 + \dots + s_n$. Its two main features are: (1) ALL $n$ participants must cooperate to reconstruct the secret, and (2) any group of fewer than $n$ participants learns absolutely nothing about the secret.

**Threshold secret sharing ($k$-out-of-$n$):** The secret is encoded as the constant term of a polynomial of degree $k-1$, and shares are evaluations of that polynomial at distinct points. Its two main features are: (1) any $k$ or more participants can reconstruct the secret using Lagrange interpolation, and (2) any group of fewer than $k$ participants learns nothing about the secret. Shamir's Secret Sharing is the standard example.

---

### Q3.8: "Write down four features of a multi-signature." / "Write down three features of a multi-signature." [S2019 Task 5a (4pts), S2020 Task 4a (3pts)]

**A:** Features of a multi-signature scheme:

1. **Unforgeability:** No subset of fewer than n signers can forge a valid combined signature.
2. **Correctness:** If all n signers produce valid partial signatures, the combined signature is valid and verifiable.
3. **Unforgeability:** No subset of fewer than n signers can forge a valid combined signature.
4. **Correctness:** If all n signers produce valid partial signatures, the combined signature is valid and verifiable.
5. **Non-repudiation:** Once a signer has contributed their partial signature, they cannot deny having signed.
6. **Compactness:** The combined multi-signature has the same size as a single signature, regardless of the number of signers.

---

### Q3.9: "Given a $n$-out-of-$n$ / 5-out-of-5 RSA signature algorithm with public key $(e, \bar{n})$, secret keys $(d_i, \bar{n})$ and modulus $\bar{n} = p \cdot q$. Write down the multi-signature generation equations for a message $m$. Write down the verification equation." [S2019 Task 5b,c (3+3 pts), S2020 Task 4b,c (3+3 pts), S2021 Task 6b,c (3+3 pts)]

**A:**

**Signing (generation):**

1.  Hash the message: $M = H(m)$
2.  Each user $u_i$ computes their partial signature: $s_i = M^{d_i} \pmod{\bar{n}}$
3.  The combined signature is the product of all partial signatures: $s = s_1 \cdot s_2 \dots s_n \pmod{\bar{n}}$

**Verification:**
Check whether $H(m) = s^e \pmod{\bar{n}}$. If they match, the signature is valid.

This works because the partial keys satisfy $d_1 + d_2 + \dots + d_n = d$ (the full private key), so multiplying the partial signatures: $s = M^{d_1} \cdot M^{d_2} \dots M^{d_n} = M^{d_1+d_2+\dots+d_n} = M^d \pmod{\bar{n}}$, and $s^e = M^{d \cdot e} = M \pmod{\bar{n}} = H(m)$.

---

### Q3.10: "Name a sample application for multi-signatures." / "Name an application for the n-out-of-n RSA signature." [S2020 Task 4d (1pt), S2021 Task 6d (1pt)]

**A:** Applications include e-voting systems (authorities jointly sign to validate votes), DNSSEC root zone signing (uses a 5-of-7 threshold scheme to sign the root DNS zone), and secure key escrow systems where multiple parties must cooperate to release a key.

---

### Q3.11: "Write down the operation to restore the secret in the case that a dealer uses Shamir's secret sharing and gives every user $u_i$ a share $(i, s_i = f(i) \pmod p)$." [W2023/24 Ex.6b (2pts)]

**A:** To restore the secret, any $k$ users apply Lagrange interpolation at $x = 0$:

$$
a_0 = f(0) = \sum_{j=1}^{k} \left[ s_j \cdot \prod_{i \neq j} \left( \frac{x_i}{x_i - x_j} \right) \right] \pmod p
$$

Where:

- $a_0$ is the secret (constant term of the polynomial)
- $s_j = f(x_j)$ is the share held by user $u_j$
- $x_i$, $x_j$ are the public evaluation points (typically just the user indices $i, j$)
- All arithmetic is performed modulo prime $p$

---

### Q3.12: "Describe the four steps of an e-voting system." / "Write down the basic mechanisms of an e-voting system." [W2022/23 Task 8 (2+8 pts), W2023/24 Ex.6c (6pts)]

**A:**

**Basic mechanisms:** The e-voting system uses two mechanisms: (1) the $n$-out-of-$n$ RSA multi-signature scheme (authorities jointly hold the signing key), and (2) blind signatures (an authority signs a message without seeing its content).

In a blind RSA signature: the voter chooses random $r$ with $\gcd(r, \bar{n}) = 1$, computes blinded message $m' = r^e \cdot m \pmod{\bar{n}}$. The authority signs: $s' = (m')^d \pmod{\bar{n}}$. The voter unblinds: $s = s' \cdot r^{-1} \pmod{\bar{n}} = m^d \pmod{\bar{n}}$.

**The four steps:**

**Step 1 — Voting and Blinding:** The voter has a vote $x$ and chooses a random number $r$. The voter computes the blinded vote $x' = r^e \cdot x \pmod{\bar{n}}$ and sends $x'$ to all $n$ authorities.

**Step 2 — Signing by Authorities:** Each authority $A_i$ uses their partial secret key $d_i$ to sign the blinded vote: $s'_i = (x')^{d_i} \pmod{\bar{n}}$. Each authority sends their partial signature back to the voter.

**Step 3 — Unblinding:** The voter multiplies all partial signatures: $s' = \prod(s'_i) \pmod{\bar{n}}$. Then the voter unblinds: $s = s' \cdot r^{-1} \pmod{\bar{n}}$. The voter sends the pair $(s, x)$ to an authority using anonymous communication (such as TOR) so the vote cannot be traced back.

**Step 4 — Verification and Counting:** The receiving authority verifies the signature by checking whether $x = s^e \pmod{\bar{n}}$. If verification passes, the vote $x$ is counted.

---

### Q3.13: "What is a blockchain?" / "What is the task of miners in a blockchain-based distributed ledger?" / "Describe a blockchain-based distributed ledger operation." [S2021 Task 7 (2+2+6 pts)]

**A:**

**What is a blockchain?** A blockchain is a distributed ledger technology where data records are organized into blocks, each block is cryptographically linked to the previous block through a hash, and every participant in the network holds a complete copy of the ledger. This design makes the ledger tamper-resistant because altering any block would invalidate all subsequent blocks.

**Task of miners:** Miners compete to solve a computationally expensive search puzzle called Proof of Work (PoW). The task is to find a nonce value such that Hash(block header including nonce) < difficulty target. The first miner to solve the puzzle broadcasts the valid block and earns a mining reward (coinbase transaction). Miners also validate transactions and maintain the integrity of the ledger.

**Distributed ledger operation (6 steps):**

1. Users create and digitally sign their transactions, then broadcast them to the network.
2. Mining nodes receive these transactions and cache them in a memory pool (mempool). A mining node selects verified transactions and assembles them into a candidate block, checking all signatures and transaction validity.
3. The candidate block is shared across the Bitcoin network.
4. All mining nodes compete to solve the Proof of Work puzzle for the candidate block.
5. The first miner to solve the puzzle broadcasts the valid block to the network.
6. Other mining nodes accept the new block and use its hash as the "previous block hash" for the next candidate block. When two miners solve simultaneously, a fork occurs — resolved by the longest chain rule.

---

## Topic 4: Anonymization & Secure MPC (5/5 exams)

### Q4.1: "Which of the following statements are true and which are false?" — Privacy T/F Blocks [S2019 Task 8a (6pts), S2020 Task 7a (6pts), S2021 Task 9 (10pts), W2022/23 Task 12d (6pts)]

**A:** These T/F statements recur across exams. Here is the complete compilation with answers and justifications:

| Statement                                                                                                                                                                                                                                        | Answer | Justification                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| After anonymizing a dataset using microaggregation, anomaly detection is always possible. [S2019]                                                                                                                                                | **F**  | Microaggregation replaces individual values with group means, which can destroy the patterns that anomaly detection relies on.                                                                                           |
| After anonymizing a dataset using multivariate microaggregation, anomaly detection is always possible. [S2020, S2021]                                                                                                                            | **F**  | Same reasoning — microaggregation distorts data, potentially making anomaly detection impossible.                                                                                                                        |
| Pseudonymization makes it impossible to link an individual to certain data anymore. [S2019]                                                                                                                                                      | **F**  | Pseudonymization is reversible with additional information (the mapping table or decryption key).                                                                                                                        |
| Pseudonymization always makes it impossible to link an individual to certain data anymore. [S2020, S2021]                                                                                                                                        | **F**  | Same reasoning — "always" makes this even more clearly false.                                                                                                                                                            |
| The GDPR demands that anonymized data is protected from being used for purposes different from the purpose the plaintext data have been collected for. [S2019 variant]                                                                           | **F**  | The GDPR does not apply to anonymous data at all. Once data is truly anonymized, it falls outside GDPR scope.                                                                                                            |
| The GDPR demands that anonymous data is protected from being used for purposes different from the purpose the plaintext data have been collected for. [S2020, S2021]                                                                             | **F**  | Same — GDPR does not apply to anonymous data.                                                                                                                                                                            |
| In order to produce a pseudonym that allows for plaintext disclosure on demand, a state-of-the-art probabilistic encryption function can be used. [S2019, S2020]                                                                                 | **F**  | A probabilistic encryption function produces different ciphertexts for the same plaintext, so you cannot reliably map back to the original. A deterministic function or lookup table is needed for on-demand disclosure. |
| A release of data is said to have the k-anonymity property if the information for each person contained in the release cannot be distinguished from at least k-1 individuals whose information also appear in the release. [S2019, S2020, S2021] | **T**  | This is the correct definition of k-anonymity.                                                                                                                                                                           |
| In the context of privacy and data protection, the GDPR is the abbreviation of "guide of data protection and privacy respectation." [S2019, S2020, S2021]                                                                                        | **F**  | GDPR stands for General Data Protection Regulation.                                                                                                                                                                      |
| Global recoding is an appropriate technique for numerical data. The values of the data attributes are simply replaced with summary statistics. [S2021]                                                                                           | **F**  | Global recoding uses generalization hierarchies (replacing values with broader categories), not summary statistics. Replacing with summary statistics describes microaggregation.                                        |
| Local recoding allows for replacing values of data attributes with summary statistics of values of other data attributes. [S2021]                                                                                                                | **F**  | Local recoding uses generalization (not summary statistics), and it replaces values from the same attribute, not other attributes.                                                                                       |
| Pseudonymization should be preferred over anonymization in all use cases. [S2021]                                                                                                                                                                | **F**  | The choice depends on the specific use case and requirements. Sometimes anonymization is more appropriate.                                                                                                               |
| In the clustering phase of multivariate microaggregation, each value of one single data attribute is made indistinguishable from k-1 other values of different data attributes in the same dataset. [S2021]                                      | **F**  | Values are made indistinguishable from values of the same attribute across different records, not different attributes.                                                                                                  |
| The anonymization technique "suppression" would always preserve the highest possible utility of a dataset. [S2021]                                                                                                                               | **F**  | Suppression removes data entirely, which reduces utility. Generalization often preserves more utility.                                                                                                                   |
| Considering the GDPR, data is not subject to a purpose limitation. [W2022/23]                                                                                                                                                                    | **F**  | Purpose limitation is one of the six core GDPR principles.                                                                                                                                                               |
| Encryption is an anonymization technique. [W2022/23]                                                                                                                                                                                             | **F**  | Encryption is pseudonymization because it is reversible with the decryption key.                                                                                                                                         |
| In local recoding a given value might be replaced with different values. [W2022/23]                                                                                                                                                              | **T**  | Different subsets may apply different generalizations to the same original value.                                                                                                                                        |
| Quasi identifiers always allow to uniquely identify a natural person. [W2022/23]                                                                                                                                                                 | **F**  | Quasi-identifiers can potentially identify someone when combined, but they do not always do so.                                                                                                                          |
| A successful membership disclosure attack can infer that an individual is represented in a dataset with high probability. [W2022/23]                                                                                                             | **T**  | This is the definition of membership disclosure.                                                                                                                                                                         |
| Hashing a dataset twice turns it anonymous. [W2022/23]                                                                                                                                                                                           | **F**  | Hashing is pseudonymization. It can be reversed through lookup tables or brute force. Applying it twice does not change this.                                                                                            |

---

### Q4.2: "Explain the difference between the generalization techniques of global and local recoding, respectively. For which kind of data is this technique appropriate?" [S2019 Task 8b (2pts), S2020 Task 7b (2pts)]

**A:** **Global recoding** replaces all occurrences of a given value with the same generalized value throughout the entire dataset. For example, all ages 20-29 are replaced with the interval [20-30] everywhere.

**Local recoding** allows the same original value to be replaced with different generalized values depending on the subset (equivalence class) it belongs to. For example, age 25 might be generalized to [20-30] in one equivalence class but to [25-35] in another.

Generalization is appropriate for **categorical and ordinal data** that has a natural hierarchy (e.g., ZIP codes: 53115 -> 531** -> 53\***; job titles: "Nurse" -> "Healthcare Worker" -> "Professional").

---

### Q4.3: "Considering pseudonymized data is still subject to the GDPR, why should personal data be pseudonymized at all?" [S2019 Task 8c (2pts), S2020 Task 7c (2pts)]

**A:** Even though pseudonymized data is still subject to the GDPR, pseudonymization provides several benefits:

1. It reduces the risk of accidental data breaches because the data is not immediately identifiable without the additional mapping information.
2. It supports the GDPR principle of data minimization by limiting exposure of direct identifiers in routine processing.
3. In the event of unauthorized access, the damage is limited because the attacker only sees pseudonyms, not real identities.
4. The GDPR explicitly encourages pseudonymization as a safeguard and grants certain regulatory advantages to organizations that pseudonymize data (e.g., broader permitted uses for research).

---

### Q4.4: "Explain the difference between univariate and multivariate microaggregation." [W2022/23 Task 12a (2pts)]

**A:** **Univariate microaggregation** applies microaggregation to each attribute independently. Each attribute is processed separately — groups of values for that single attribute are replaced with their group mean. This does NOT ensure k-anonymity because the grouping is done per attribute, not across all quasi-identifier attributes simultaneously.

**Multivariate microaggregation** applies microaggregation to all quasi-identifier attributes at once. Records are clustered based on all their attribute values together, and each cluster's values are replaced by the cluster's centroid (mean). This approach ensures k-anonymity because the grouping considers all quasi-identifiers simultaneously.

---

### Q4.5: "Define k-anonymity as discussed in the lecture." [W2022/23 Task 12b (1pt)]

**A:** A release of data is said to have the k-anonymity property if every occurring combination of values of quasi-identifiers appears for at least k individuals in the dataset. The groups of individuals sharing the same quasi-identifier values are called equivalence classes, and k must be greater than 1.

---

### Q4.6: "Define attribute disclosure as discussed in the lecture." [W2022/23 Task 12c (1pt)]

**A:** Attribute disclosure occurs when an attacker learns the value of a sensitive attribute for a specific individual, even without necessarily matching the individual to a specific record in the dataset. It is possible whenever all records in an equivalence class share the same sensitive attribute value — the attacker knows the target is in that class and therefore knows their sensitive value.

---

### Q4.7: "Define the property distinct l-diversity for a dataset." [W2023/24 Ex.12b (2pts)]

**A:** An equivalence class fulfills distinct l-diversity if there are at least l different values for the sensitive attribute within that class. A table meets the distinct l-diversity requirement if ALL of its equivalence classes are l-diverse, meaning every equivalence class contains at least l distinct sensitive attribute values. The value of l must be greater than 1.

---

### Q4.8: "Write down the similarities and differences between the prosecutor and journalist attacker." [W2023/24 Ex.12a (2pts)]

**A:** **Similarities:** Both the prosecutor and journalist attacker target a specific individual (as opposed to the marketer, who targets many). Both attempt to re-identify a single target in the dataset.

**Differences:** The prosecutor attacker **assumes** that the target individual is contained in the dataset, so they focus entirely on linking the target to a specific record. The journalist attacker does **not** know whether the target is in the dataset and must first determine if the target is present before attempting to link. Because the journalist faces an additional uncertainty, the journalist model is considered weaker (harder to succeed).

---

### Q4.9: "Define the semi-honest adversary." [W2022/23 Task 13a (2pts)]

**A:** A semi-honest adversary follows the protocol correctly — all outputs, computations, and sent messages are exactly as specified by the protocol. However, the semi-honest adversary may use their own knowledge and any received data to infer more information than the protocol intended to reveal. This type of adversary violates mainly privacy constraints, not correctness of the computation.

---

### Q4.10: "Define the prosecutor attacker model." [W2022/23 Task 13b (2pts)]

**A:** The prosecutor attacker targets a specific individual and assumes that the individual is contained in the published dataset. The prosecutor uses background knowledge about the target's quasi-identifier values to locate the target within the dataset and infer sensitive attribute values. Because the prosecutor already knows the target is present, the attack focuses solely on linking and attribute inference.

---

### Q4.11: "Which goals should be reached by an oblivious transfer?" [W2022/23 Task 13c (2pts)]

**A:** An oblivious transfer (OT 1-out-of-2) protocol must achieve four goals:

1. Alice holds two secret messages $M_0$ and $M_1$.
2. Bob receives exactly one of the two messages — specifically $M_b$, where $b$ is Bob's choice of either 0 or 1.
3. Alice does not learn which message Bob chose to receive (Bob's choice remains secret).
4. Bob learns nothing about the message he did not choose (the unchosen message remains secret).

---

### Q4.12: "Describe the advantage of GRR3 and how it is reached." [W2022/23 Task 13d (4pts)]

**A:** GRR3 (Garbled Row Reduction 3) reduces the size of each garbled truth table from 4 rows to 3 rows, saving bandwidth.

**How it is achieved:** GRR3 builds on Point & Permute, which ensures the garbled table is sorted by random sorting bits so Bob can find the correct row in exactly one decryption attempt. Because the table is sorted, the top row (the row corresponding to sorting bits 00) is always in a predictable position. Alice chooses the output label for this top row such that the encrypted value is a zero-bitstring of length N. Since the top row is known to always be zeros, it does not need to be transmitted to Bob — Bob knows that if his sorting bits select the top row, the result is the zero bitstring. This reduces the transmitted table from 4 rows to 3 rows per gate.

**Important:** GRR3 reduces the number of rows per gate, NOT the number of gates in the circuit.

---

### Q4.13: "Describe the advantage of point-and-permute over the raw garbled circuits technique." [W2023/24 Ex.12c (1pt)]

**A:** In the classical garbled circuits approach, Bob may need up to 4 decryption attempts per gate to find the correct row (trying each row until one decrypts successfully). In Point & Permute, each wire label is augmented with a random sorting bit, and the garbled table is sorted by these bits. Because Bob knows the sorting bits of his input labels, he can immediately identify the correct row and decrypt it in exactly one attempt. There is no security loss because the sorting bits are random and independent of the actual input values.

---

### Q4.14: "Fill in the empty lines to implement the given circuit in the Bristol Fashion Format." [W2023/24 Ex.12d (5pts)]

**A:** The Bristol Fashion Format (BFF) is a standardized text format for representing boolean circuits used in the jigg library for secure multiparty computation. The format is structured as follows:

- **Line 1:** Total number of gates in the circuit.
- **Line 2:** Total number of wires in the circuit.
- **Line 3:** Number and size of input groups (e.g., "2 2 2" means 2 input groups, each of size 2).
- **Line 4:** Number and size of output groups (e.g., "1 1" means 1 output group of size 1).
- **Blank line**
- **Gate lines:** Each gate is written as: `num_inputs num_outputs input_wire(s) output_wire gate_type`

For a specific circuit, each gate line specifies: the number of input wires, the number of output wires, the wire indices for inputs, the wire index for the output, and the gate operation (XOR, AND, NOT, etc.).

The exam question gave a specific circuit diagram with Alice's inputs (wires 0, 2), Bob's inputs (wires 1, 3), and gates (XOR, NOT, AND) producing an output. Each gate must be translated into the BFF line format following the wire numbering convention where input wires start at 0 and subsequent wires are numbered sequentially.

---

## Topic 5: Binary Exploitation / ROP (S2019 20pts, W2023/24 10pts)

### Q5.1: "How does a code injection attack impact on the CFG of the attacked program?" [S2019 Task 3a (2pts)]

**A:** A code injection attack introduces entirely new code (shellcode) that the original program was never designed to execute. This new code is not part of the program's original control flow graph — it represents new nodes and edges that did not exist in the CFG. The attack diverts the execution from the original CFG to the injected code by overwriting a return address or function pointer.

---

### Q5.2: "How does a code reuse attack impact on the CFG of the attacked program?" [S2019 Task 3b (2pts)]

**A:** A code reuse attack does not introduce any new code. Instead, it chains together existing code fragments (gadgets) that are already part of the program or its libraries. The individual instructions being executed all exist in the original CFG, but the order in which they are executed creates new execution paths that were never intended. The attack adds new edges to the CFG by manipulating the stack to redirect control flow through a sequence of existing code snippets.

---

### Q5.3: "Describe the idea of return-oriented programming (ROP). Which information is required for an attacker in order to successfully attack a program using ROP? How are these used during the attack?" [S2019 Task 3c (8pts)]

**A:** ROP is a technique for exploiting buffer overflows when DEP (Data Execution Prevention) is active, which prevents injected code from being executed. Instead of injecting new code, ROP reuses short instruction sequences already present in the program or its loaded libraries. These sequences are called gadgets, and each one ends with a `ret` instruction.

**How it works:** The attacker overflows a buffer to overwrite the return address on the stack. When the function returns, `ret` pops the top of the stack into the instruction pointer (rip), redirecting execution to the first gadget. That gadget executes its instructions and its own `ret` pops the next address from the stack, jumping to the second gadget, and so on. This chain of gadgets can perform arbitrary computations.

**Information required:**

1. The addresses of useful gadgets in the program binary or loaded libraries.
2. The offset from the buffer to the return address on the stack (to know how much padding to write).
3. The addresses of any strings or data needed (e.g., "/bin/sh").
4. The library base address (if ASLR is active, this must be leaked at runtime).

**How this information is used:** The attacker constructs a payload that fills the buffer with padding, overwrites the saved rbp, and then writes the ROP chain starting at the return address position. Each entry in the chain is either a gadget address or an argument value that the preceding gadget will pop into a register.

---

### Q5.4: "Describe the idea of Control Flow Integrity (CFI) checking. What is the goal? How does CFI checking work?" [S2019 Task 3d (8pts)]

**A:** Control Flow Integrity (CFI) is a defense mechanism whose goal is to ensure that a program's execution follows only the paths defined in its original control flow graph (CFG). It prevents attackers from hijacking control flow through techniques like ROP or return-to-libc.

**How CFI works:** At compile time, the program's valid CFG is computed through static analysis, identifying all legitimate targets for indirect branches (function calls through pointers, returns, and indirect jumps). At runtime, before each indirect control flow transfer, an instrumented check verifies that the target address is in the set of valid targets for that particular transfer point. If the target is not valid, the program aborts.

CFI effectively prevents ROP because the attacker's chain of gadgets creates control flow transfers that are not in the original CFG. Each `ret` to a gadget address would be checked and found invalid (since the gadget was not a legitimate return target for that call site), causing the program to terminate before the exploit executes.

---

### Q5.5: "Prepare the payload to overflow the local variable x to exploit a program with a ROP chain which calls execve('/bin/sh', NULL, NULL). Write it into the stack diagram with brief explanations." [W2023/24 Ex.4 (10pts)]

**A:** Given information:

- Base address of library: 0x7fff 4000 0000
- Gadget offsets: pop rax; ret = 0x42, pop rdi; pop rdx; ret = 0x1000, pop rsi; ret = 0x08 0400, syscall = 0xdead
- String "/bin/sh\0" address: 0x7fff f7ff dab0
- execve syscall: rax = 0x3b, rdi = filename, rsi = argv (NULL), rdx = envp (NULL)
- x at 7fff ffff dc50, saved rbp at dc58, return address at dc60

**Absolute gadget addresses** (base + offset):

- pop rax; ret = 0x7fff 4000 0042
- pop rdi; pop rdx; ret = 0x7fff 4000 1000
- pop rsi; ret = 0x7fff 4008 0400
- syscall = 0x7fff 4000 dead

**Stack layout (payload):**

| Address        | Value (little-endian) | Explanation                         |
| -------------- | --------------------- | ----------------------------------- |
| 7fff ffff dc50 | (any 8 bytes)         | padding (overwrites x)              |
| 7fff ffff dc58 | (any 8 bytes)         | padding (overwrites saved rbp)      |
| 7fff ffff dc60 | 42 00 00 40 ff 7f - - | pop rax; ret gadget                 |
| 7fff ffff dc68 | 3b - - - - - - -      | 0x3b = execve syscall number -> rax |
| 7fff ffff dc70 | 00 10 00 40 ff 7f - - | pop rdi; pop rdx; ret gadget        |
| 7fff ffff dc78 | b0 da ff f7 ff 7f - - | address of "/bin/sh\0" -> rdi       |
| 7fff ffff dc80 | - - - - - - - -       | 0x0 (NULL) -> rdx (envp)            |
| 7fff ffff dc88 | 00 04 08 40 ff 7f - - | pop rsi; ret gadget                 |
| 7fff ffff dc90 | - - - - - - - -       | 0x0 (NULL) -> rsi (argv)            |
| 7fff ffff dc98 | ad de 00 40 ff 7f - - | syscall gadget                      |

Note: All addresses are written in little-endian byte order. Dashes represent 0x00 bytes.

---

## Topic 6: Malware Analysis (W2023/24 only)

### Q6.1: "In 2-3 sentences, explain the obfuscation technique stack strings, what they are used for and why they work." [W2023/24 Ex.5a (3pts)]

**A:** Stack strings are an obfuscation technique where individual parts of a string are stored as separate integer values that are pushed onto the stack as local variables. They are used to hide sensitive strings (like IP addresses, registry keys, or C&C server URLs) from static analysis tools that scan the binary's data section for readable text. They work because the compiler allocates local variables contiguously on the stack, so at runtime these separate integers form a readable string in memory, but static analysis tools never see the string as a single contiguous entity in the binary.

---

### Q6.2: "Given the following assembly instructions of the main function, conceptually explain how you would use a debugger to circumvent the anti-debugging functionality, and execute the target function super_secret_target_func." [W2023/24 Ex.5b (4pts)]

**A:** The assembly shows that the program calls IsDebuggerPresent at address 0x140001487, tests the result with `test eax, eax` at 0x140001489, and uses `je 0x140001497` at 0x14000148b. If eax is nonzero (debugger detected), execution falls through to `exit`; if zero (no debugger), it jumps to 0x140001497 which calls super_secret_target_func.

**Method 1 (Modify return value):** Set a breakpoint at 0x140001489 (right after the IsDebuggerPresent call). When the breakpoint hits, the return value in eax will be 1 (debugger detected). Use the debugger to set eax = 0. Continue execution — the `je` instruction will see the zero flag set and jump to 0x140001497, executing super_secret_target_func.

**Method 2 (Modify instruction pointer):** Set a breakpoint at 0x14000148b (the conditional jump). When the breakpoint hits, directly set the instruction pointer rip to 0x140001497 (the address of the call to super_secret_target_func), skipping the anti-debug check entirely.

**Method 3 (Patch the binary):** Change the `je` instruction at 0x14000148b to an unconditional `jmp` so execution always goes to super_secret_target_func regardless of the debugger check.

---

### Q6.3: "Given the following diagram of communication between an infected client and a C&C server, explain the characteristic technique of this approach, and two advantages compared to the naive approach of directly communicating with the hardcoded IP 1.1.1.1." [W2023/24 Ex.5c (3pts)]

**A:** The diagram shows the malware using **domain flux** (also called fast flux). Instead of communicating directly with a hardcoded IP address, the malware contains a Domain Generation Algorithm (DGA) that produces multiple domain names (b1.c2.com, b2.c2.com, b3.c2.com, b4.c2.com). Each domain can resolve to a different IP address, and the C&C operator only needs to register one of the generated domains and point it to their current server.

**Advantage 1 — Resilience against takedowns:** If defenders block one domain or shut down one server, the malware simply moves to another generated domain that resolves to a different IP address. There is no single point of failure.

**Advantage 2 — Difficulty of blocking:** Defenders cannot easily blacklist all possible domains because the DGA generates thousands of new domains. Predicting and pre-emptively blocking all future domains requires reverse-engineering the DGA algorithm.

---

## Topic 7: Fuzzing (W2022/23, W2023/24 — nearly identical questions)

### Q7.1: "When is instrumentation used and what is done during the instrumentation step?" / "At what point during the build process of the library is the instrumentation being done? Describe how the instrumentation is being done." [W2022/23 Task 5a (2pts), W2023/24 Ex.7a (3pts)]

**A:** Instrumentation is performed at **compile time**, before the program is executed. During the instrumentation step, the compiler inserts additional tracking code (such as calls to `__sanitizer_cov_trace_pc`) at the beginning of each basic block in the program's control flow graph. These inserted calls record which basic blocks and edges are reached during execution, enabling the fuzzer to measure code coverage and determine whether a new test input has discovered previously unseen code paths.

For LibFuzzer, instrumentation is done by compiling with `-fsanitize=fuzzer-no-link`. For AFL++, instrumentation is done by using AFL's custom compiler wrappers (`afl-clang-fast` or `afl-clang-fast++`).

---

### Q7.2: "Which kind of vulnerabilities does the AddressSanitizer detect and how is it done?" / "Describe one kind of vulnerability that can be detected with the Address Sanitizer (ASAN). How does ASAN detect the vulnerability?" [W2022/23 Task 5b (4pts), W2023/24 Ex.7b (3pts)]

**A:** The Address Sanitizer (ASan) detects memory safety vulnerabilities including **stack buffer overflows**, **heap buffer overflows**, **heap use-after-free**, **use-after-scope**, and **use-after-return**.

**How it works:** ASan creates **poisoned redzones** — forbidden memory regions — around stack variables, global variables, and heap allocations. The instrumentation module inserts redzones at compile time for stack and global objects. The runtime component replaces the standard memory allocator (malloc, free, etc.) to create redzones around heap allocations and to delay the reuse of freed memory regions. If the program reads from or writes to a redzone, ASan immediately reports the error with detailed diagnostic information (type of violation, offending address, surrounding memory layout) and terminates the program.

ASan is enabled by compiling with `-fsanitize=address`.

---

### Q7.3: "Given the following list of labels and the empty diagram: assign the labels so that the diagram represents the Coverage Guided Fuzzing Algorithm." [W2022/23 Task 5c (4pts), W2023/24 Ex.7c (4pts)]

**A:** The coverage-guided fuzzing algorithm follows this flow:

```
Seed Files --> Code Coverage Evaluation --> Crash? (or ASan)
                                              |
                                         Yes: Done/Solution
                                         No:  Selection --> Mutation --> (loop back to Code Coverage Evaluation)
```

The six labels in order:

| Position | Label                        | Purpose                                                              |
| -------- | ---------------------------- | -------------------------------------------------------------------- |
| 1        | **Seed Files**               | Initial set of valid input files                                     |
| 2        | **Code Coverage Evaluation** | Execute input with instrumented program, record which paths are hit  |
| 3        | **Crash (or ASan etc.)**     | Check if input caused a crash or sanitizer violation                 |
| 4        | **Done / Solution**          | If crash found, save finding and report                              |
| 5        | **Selection**                | Keep inputs that discovered new code coverage in the corpus          |
| 6        | **Mutation**                 | Modify selected inputs to create new test cases, loop back to step 2 |

The flow: Seed Files -> Code Coverage Evaluation -> Crash check -> (if No) -> Selection -> Mutation -> (back to Code Coverage Evaluation). If Crash = Yes -> Done.

---

## Topic 8: Topological Data Analysis (W2023/24 only)

### Q8.1: "Match the persistence diagrams to the captioned point clouds (Filled Torus, Hollow Sphere, Hollow Torus, 2D Ring). Briefly justify your answers." [W2023/24 Ex.11a (2pts)]

**A:** To match persistence diagrams to shapes, count the number of persistent features (points far from the diagonal) in each homology dimension:

| Shape                | H₀ persistent | H₁ persistent | H₂ persistent | How to identify                                      |
| -------------------- | :-----------: | :-----------: | :-----------: | ---------------------------------------------------- |
| **2D Ring (circle)** |       1       |       1       |       0       | One loop, no voids                                   |
| **Filled Torus**     |       1       |       1       |       0       | One loop (central circle), no voids (solid interior) |
| **Hollow Sphere**    |       1       |       0       |       1       | No persistent loops, one void — UNIQUE               |
| **Hollow Torus**     |       1       |       2       |       1       | Two loops + one void — MOST features                 |

**Justification:** The hollow sphere is the easiest to identify because it is the only shape with no persistent H₁ features but one persistent H₂ feature. The hollow torus is identified by having the most features (2 persistent H₁ + 1 persistent H₂). The 2D ring and filled torus both have 1 persistent H₁ and 0 H₂, so they are distinguished by the scale at which the H₁ feature appears.

---

### Q8.2: "Given two topological spaces X and Y, define homotopy equivalence and homeomorphism." [W2023/24 Ex.11b (4pts)]

**A:** **Homeomorphism:** Two topological spaces X and Y are homeomorphic if there exists a continuous bijection f: X -> Y whose inverse f^{-1}: Y -> X is also continuous. Such a function f is called a homeomorphism. Homeomorphic spaces are topologically identical — every topological property of X is shared by Y and vice versa. Informally, a homeomorphism is a reversible rubber-sheet deformation.

**Homotopy equivalence:** Two topological spaces X and Y are homotopy equivalent if there exist continuous maps f: X -> Y and g: Y -> X such that the composition g o f is homotopic to the identity map on X, and the composition f o g is homotopic to the identity map on Y. Two maps are homotopic if one can be continuously deformed into the other.

Homeomorphism is the stronger condition. Every homeomorphism implies homotopy equivalence, but the converse is not true. Homotopy equivalence allows spaces of different dimensions to be "equivalent."

---

### Q8.3: "Consider two topological spaces: Space X is a solid torus, and space Y is a hollow torus. Are X and Y homotopy equivalent? Justify your answer." [W2023/24 Ex.11c (2pts)]

**A:** No, a solid torus and a hollow torus are NOT homotopy equivalent.

The solid torus (S¹ x D²) is homotopy equivalent to a circle (S¹), because the filled disk cross-section can be continuously contracted to a point, leaving only the central circle. This gives H₁ = Z (one independent loop).

The hollow torus (T² = S¹ x S¹) has H₁ = Z² (two independent loops — one going around the ring, one going through the tube).

Since homology is a homotopy invariant (homotopy equivalent spaces must have the same homology groups), and the H₁ groups differ (Z vs Z²), the solid torus and hollow torus cannot be homotopy equivalent.

---

### Q8.4: "Give an example for two spaces that are homotopy equivalent, but not homeomorphic. Explain the reasoning." [W2023/24 Ex.11d (2pts)]

**A:** A solid disk D² and a single point {p} are homotopy equivalent because the disk can be continuously contracted to its center point through a deformation retraction. However, they are not homeomorphic because there is no continuous bijection between them — the disk is a two-dimensional space with infinitely many points, while a single point is zero-dimensional.

Alternative example: A solid torus (S¹ x D²) and a circle (S¹) are homotopy equivalent (the solid torus deformation retracts onto its central circle) but not homeomorphic (one is 3-dimensional, the other is 1-dimensional).

---

## Topic 9: Device Identification (W2022/23, W2023/24 — nearly identical questions)

### Q9.1: "Give an example for why utilizing device identification techniques can benefit a defensive actor as discussed in the lecture. In what way can the defensive actor use identifying data in your example?" [W2022/23 Task 3a (3pts), W2023/24 Ex.9a (3pts)]

**A:** A corporate network administrator maintains an RF fingerprint database of all authorized wireless devices in the organization. When an unknown device attempts to connect to the network using a spoofed MAC address to impersonate an authorized device, the wireless intrusion detection system (WIDS) compares the device's physical RF fingerprint against the database of stored fingerprints. Because the physical RF fingerprint originates from manufacturing variations in the wireless chip and cannot be easily forged, the WIDS detects that the fingerprint does not match the stored profile for that MAC address, flags the device as an unauthorized intruder, and blocks the connection.

---

### Q9.2: "Name a collectible characteristic of a wireless transmission to be used as indirect device identifying data (DID) and explain why it qualifies as an indirect DID." [W2022/23 Task 3b (3pts)]

**A:** A collectible characteristic that qualifies as indirect DID is the **clock skew (frequency offset)** of a wireless transmission. It qualifies as indirect DID because while different devices exhibit slightly different clock skew values due to manufacturing variations in their oscillators, the clock skew alone is not precise enough to uniquely identify a specific device. It can only help narrow down the set of candidate devices when combined with other identifying information. By definition, indirect DID are data that by themselves are not sufficient for unique identification but provide supplementary information to support the identification process.

Other examples of indirect DID include signal strength (RSS), scrambler seed sequence, and modulation errors.

---

### Q9.3: "Name two collectable characteristics of a wireless transmission to be used as direct device identifying data (DID) and explain why they qualify as direct DID." [W2023/24 Ex.9b (3pts)]

**A:** Two characteristics that qualify as direct DID:

1. **MAC address:** A globally unique hardware identifier assigned to the wireless chip by the manufacturer. It qualifies as direct DID because it is globally unique by design and directly tied to a specific physical device, making identification possible from this single data point alone.

2. **IMEI (International Mobile Equipment Identity):** A unique number assigned to every mobile device, transmitted in cellular protocol headers. It qualifies as direct DID because, like the MAC address, it is globally unique and directly identifies the specific physical device without requiring any additional information.

Direct DID are device identifying data that qualify for device identification by themselves — a single direct DID is sufficient on its own to uniquely identify or distinguish a device.

---

### Q9.4: "Assume you want to know whether a target device is still sending and in range of your antenna. Its communication is completely encrypted. Name a passive device identification technique that you could use. Why does it work? What drawbacks does your suggested technique have?" [W2022/23 Task 3c (4pts)]

**A:** When all communication is encrypted (including headers and payload), packet-content-based techniques cannot be used. However, signal-based passive techniques still work.

**Suitable technique:** Transient-based identification (or modulation-based identification). This technique analyzes the physical characteristics of the RF signal — specifically the transient signal shape during power ramp-up before each new transmission, or modulation errors like frequency offset and I/Q origin offset.

**Why it works:** The physical characteristics of the transmission are determined by the hardware — the wireless chip's manufacturing imperfections — not by the encrypted data content. Different devices produce distinct signal profiles that can be classified even without reading any packet data.

**Drawbacks:**

1. Requires specialized hardware (a Software Defined Radio or high-resolution receiver) to capture raw RF signals with sufficient precision.
2. Requires a pre-trained classifier that has previously observed the target device's signals — it cannot identify a device that has never been seen before.
3. Environmental factors such as distance, interference, and multipath propagation can degrade accuracy.
4. The technique may not work reliably in all conditions.

---

### Q9.5: "Describe a scenario where using active device identification may be harmful to an attacking fingerprinter but passive device identification can be utilized effectively. Why can active device identification be harmful to the attacker but passive device identification is not in your given scenario?" [W2023/24 Ex.9c (4pts)]

**A:** **Scenario:** An attacker wants to identify and track a specific device within a corporate network that is monitored by a wireless intrusion detection system (WIDS). The network security team actively monitors for rogue access points and unusual wireless traffic patterns.

**Why active DI is harmful:** Active device identification requires the attacker to transmit packets — for example, broadcasting beacon frames in a Known Beacon Attack or impersonating an access point in a Karma Attack. The WIDS would detect these unusual transmissions originating from an unrecognized source, immediately alerting the security team. The attacker's physical location could be triangulated based on the signal strength of their transmissions, leading to their discovery and potentially their arrest.

**Why passive DI works safely:** Passive device identification only requires the attacker to listen to existing wireless traffic without ever transmitting a single packet. Signal-based techniques such as transient analysis or modulation-based identification can be performed purely through observation. Since the attacker never transmits, the WIDS has no way to detect the fingerprinter's presence, and the attacker remains completely invisible to the monitored network.

---

## Topic 10: Wireless Security (S2019, S2020, S2021, W2022/23) [DROPPED — not in current curriculum]

### Q10.1: "Why is security by proximity a flawed security strategy? Use an example to justify." [S2019 Task 2a,b (2+2 pts), S2021 Task 1a (3pts), Online Test Q2 (2pts)]

**A:** [DROPPED — not in current curriculum]

Security by proximity is flawed because the received signal power at a receiver is not solely controlled by the sender. An attacker can use amplifiers, directional antennas, or relay equipment to extend their effective range or fake physical proximity.

**Example:** A relay attack against a Passive Keyless Entry System (PKES) for cars. The car's key fob and the car communicate via short-range radio, assuming that if the signal is received, the key must be physically nearby. An attacker uses two relay devices — one near the car and one near the key fob (e.g., in the owner's house). The relay extends the communication range, making the car believe the key is nearby when it is actually far away, allowing the attacker to unlock and start the car.

---

### Q10.2: "Name the three antenna types presented in the lecture. Point out one that is used more frequently by attackers. Explain why." [S2020 Task 1a (2pts), W2022/23 Task 1a (3pts)]

**A:** [DROPPED — not in current curriculum]

The three antenna types are:

1. **Omnidirectional antenna:** Radiates signal equally in all directions (360 degrees).
2. **Semi-directional (sector) antenna:** Focuses the signal in a specific direction/sector.
3. **Directional (high-gain/parabolic) antenna:** Focuses the signal into a narrow beam.

Attackers typically prefer **directional antennas** because: (1) they can focus energy in a specific direction, allowing attacks from a greater distance while remaining harder to detect, and (2) they minimize the attacker's signal footprint, making it harder for defenders to locate the source of the attack.

---

### Q10.3: "Name a protocol aware jamming attack and a protocol oblivious jamming attack on 802.11a Wi-Fi. Explain the differences." [S2020 Task 1b,c (2+2 pts), S2021 Task 1b (4pts), W2022/23 Task 1c (4pts)]

**A:** [DROPPED — not in current curriculum]

**Protocol oblivious jamming attack:** Barrage Jamming — the attacker continuously transmits noise across the entire frequency band, drowning out all legitimate communication. It is "protocol oblivious" because the attacker does not need any knowledge of the protocol being used; they simply flood the channel with noise.

**Protocol aware jamming attack:** Preamble Corruption (or Pilot Jamming, Control Information Jamming) — the attacker targets specific parts of the protocol frame (such as the preamble or control fields) with precisely timed interference. It is "protocol aware" because the attacker must understand the protocol's frame structure and timing to know exactly when and where to jam.

**Differences:** Protocol oblivious attacks require no knowledge of the protocol and jam everything indiscriminately, but they waste energy and are easier to detect. Protocol aware attacks are more efficient (less energy, harder to detect) because they target only critical protocol elements, but they require detailed knowledge of the protocol's structure, timing, and frequency usage.

---

### Q10.4: "What are drawbacks for an attacker when using a protocol aware jamming attack over a protocol oblivious jamming attack?" / "What are the drawbacks for the attacker?" [S2019 Task 2f (2pts), S2020 Task 1d (2pts)]

**A:** [DROPPED — not in current curriculum]

1. The attacker needs detailed knowledge of the communication protocol (frame structure, timing, frequencies).
2. The attacker needs specialized and more expensive equipment capable of precisely timed transmissions.
3. The attack is protocol-specific — if the target switches protocols or frequencies, the attack may fail.
4. Developing and calibrating the attack is more complex and time-consuming.

---

### Q10.5: "Name two techniques that make wireless communication more robust against narrow-band jamming attacks. Pick one and explain: Why does this technique result in a less potential overall data rate?" [S2021 Task 1c (3pts)]

**A:** [DROPPED — not in current curriculum]

Two mitigation techniques against narrow-band jamming:

1. **FHSS (Frequency Hopping Spread Spectrum):** The transmitter rapidly hops between different frequency channels according to a pre-shared hopping sequence. A narrow-band jammer can only disrupt one channel at a time, missing the signal as it hops away. It results in a lower data rate because the transmitter remains silent on all other channels while transmitting on the current hop frequency, and time is lost during channel switching.

2. **DSSS (Direct Sequence Spread Spectrum):** The signal is spread across a much wider frequency range using a pre-shared spreading code (chipping code). The signal power per frequency is reduced to near noise level, making it harder for a jammer to disrupt. It results in a lower data rate because spreading the signal over a wider bandwidth means less transmission power per unit bandwidth, and the spreading process uses bandwidth that could otherwise carry more data.

---

### Q10.6: "What makes the WPA2 handshake vulnerable?" [S2020 Task 1e (2pts), S2021 Task 2d (2pts)]

**A:** [DROPPED — not in current curriculum]

The WPA2 4-way handshake is vulnerable because it derives the Pairwise Transient Key (PTK) from the Pre-Shared Key (PSK/password), two MAC addresses (AP and client), and two nonces. An attacker can capture the 4-way handshake (which includes the nonces and MAC addresses in cleartext) and then perform an offline dictionary or brute-force attack against the PSK. Since the handshake messages contain all the information needed to verify a candidate password, the attacker can test millions of passwords per second offline without needing to interact with the network again.

---

### Q10.7: Wi-Fi Security True/False [S2021 Task 2a (2pts), W2022/23 Task 2a (4pts)]

**A:** [DROPPED — not in current curriculum]

| Statement                                                                                                                                                                                                                                                          | Answer | Justification                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------ |
| Open System Authentication describes a method where any client can connect to a Wi-Fi network without knowledge of any secrets. [S2021, W2022/23]                                                                                                                  | **T**  | Open System Authentication accepts any client — no credentials are needed.                                                     |
| An access point of a Wi-Fi network secured by MAC-address filtering only accepts connections by devices using a MAC address matching to its pre-set list. [S2021, W2022/23]                                                                                        | **T**  | This is correct by definition, though MAC addresses can be spoofed.                                                            |
| WEP supports the different keylengths 32 bits, 40 bits, and 104 bits. [S2021, W2022/23]                                                                                                                                                                            | **F**  | WEP supports 40-bit and 104-bit keys. There is no 32-bit key option.                                                           |
| WEP's successor WPA was a major redesign of which WPA2 adopted most aspects, even though WPA still used the broken RC4. [S2021] / WPA, the successor of WEP, while still using the broken RC4 was a major redesign, of which WPA2 adopted most aspects. [W2022/23] | **F**  | WPA was an interim patch, not a major redesign. WPA2 was the major redesign (based on 802.11i, using AES-CCMP instead of RC4). |

---

### Q10.8: "What weakness of RC4 does the FMS attack exploit?" [S2021 Task 2b (2pts), W2022/23 Task 2b (2pts)]

**A:** [DROPPED — not in current curriculum]

The FMS (Fluhrer-Mantin-Shamir) attack exploits a weakness in the RC4 Key Scheduling Algorithm (KSA). When certain "weak" initialization vectors (IVs) are used, the first bytes of the RC4 keystream are statistically correlated with the secret key bytes. By collecting many packets encrypted with different IVs (particularly weak IVs), the attacker can statistically recover the WEP key byte by byte.

---

### Q10.9: "You are eavesdropping all nearby Wi-Fi packets. You notice a WEP encrypted communication. What packets can you use to perform the FMS attack? Explain what makes these packets usable." [S2021 Task 2c (4pts), W2022/23 Task 2c (4pts)]

**A:** [DROPPED — not in current curriculum]

The attacker uses **ARP packets** (specifically ARP request/response packets) to perform the FMS attack. ARP packets are usable for two reasons:

1. **Fixed known structure:** ARP packets have a well-known, fixed-size format. The attacker knows the plaintext of certain bytes (like the Ethernet type field), which provides a known plaintext for XOR comparison with the encrypted bytes.
2. **Predictable and stimulable:** ARP packets are short and frequent. The attacker can also stimulate additional ARP traffic (by deauthenticating a client, causing it to re-associate and generate new ARP requests), thereby collecting many packets with different IVs quickly.

By collecting enough packets with "weak" IVs, the attacker correlates the first keystream bytes with the secret key and recovers the WEP key.

---

### Q10.10: "Explain how the relay attack works with regards to passive keyless entry systems. What security strategy is circumvented?" [W2022/23 Task 1b (3pts)]

**A:** [DROPPED — not in current curriculum]

In a relay attack against a Passive Keyless Entry System (PKES), the attacker uses two relay devices positioned between the car and the key fob. One device is placed near the car, and the other near the key fob (which may be inside the owner's house). The relay devices extend the short-range communication channel between the car and the key fob, making the car believe the key is in close proximity. The car then unlocks and allows the engine to start, even though the legitimate key holder may be far away.

The security strategy circumvented is **security by proximity** — the assumption that if a signal can be received, the sender must be physically nearby.

---

### Q10.11 (Online Test): "Which of the following attacks are protocol aware jamming attacks? (Barrage Jamming / Preamble Corruption / Pilot Jamming / Control Information Jamming)" [Online Test Q1 (2pts)]

**A:** [DROPPED — not in current curriculum]

Protocol aware jamming attacks: **Preamble Corruption**, **Pilot Jamming**, and **Control Information Jamming**. Barrage Jamming is protocol oblivious (it jams everything indiscriminately).

---

## Topic 11: Web Security / SSO (W2022/23 only)

### Q11.1: "Name the three phases of a Single Sign-On (SSO) protocol." [W2022/23 Task 11a (1.5pts)]

**A:** [DROPPED — not in current curriculum, appeared only on transitional exam]

The three phases of an SSO protocol are:

1. **Discovery Phase:** The Service Provider (SP) identifies which Identity Provider (IdP) is responsible for authenticating the user.
2. **Authentication Phase:** The user authenticates with the IdP (e.g., by entering credentials). The IdP generates an authentication token.
3. **Token Exchange Phase:** The authentication token is sent from the IdP to the SP, which verifies it and grants the user access.

---

### Q11.2: "Draw arrows for every communication step between different parties as in the Malicious Endpoint (Broken User Authentication) attack in chronologically correct order. Mark your arrows with the number of the phase they belong to." [W2022/23 Task 11b,c (6+2.5 pts)]

**A:** [DROPPED — not in current curriculum, appeared only on transitional exam]

In the Malicious Endpoint (Broken User Authentication) attack, the attacker operates a malicious Identity Provider (Attacker IdP). The attack exploits the fact that the victim's SP trusts any IdP that completes the SSO protocol. The communication flow is:

1. (Discovery) Victim -> Honest SP: Initiates login
2. (Discovery) Honest SP -> Victim: Redirects to IdP discovery
3. (Discovery) Victim -> Attacker IdP: Victim is tricked into selecting the Attacker IdP (e.g., via phishing)
4. (Authentication) Attacker IdP -> Victim: Presents a fake authentication page
5. (Authentication) Victim -> Attacker IdP: Victim enters credentials (which the attacker now has)
6. (Token Exchange) Attacker IdP -> Honest SP: Sends a forged authentication token
7. (Token Exchange) Honest SP -> Victim: Grants access based on the forged token

The core vulnerability is that the SP does not properly authenticate the IdP or validate the authentication token's origin, allowing the attacker's IdP to impersonate a legitimate one.

---

## Topic 12: Anomaly Detection (S2019, S2020, S2021, W2022/23) [DROPPED — not in current curriculum]

### Q12.1: Anomaly Detection True/False [S2019 Task 7a (2pts), S2020 Task 8a (2pts), S2021 Task 10a (2pts), W2022/23 Task 14a (2pts)]

**A:** [DROPPED — not in current curriculum]

| Statement                                                                                                                                  | Answer | Justification                                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| In general, data deformation can improve the detection quality of DBScan and linear SVMs but not for the 2-means algorithm. [S2019]        | **F**  | Data deformation (kernel tricks) can improve all three, but the specific claim about 2-means is incorrect — k-means can also benefit from data transformation.                                                         |
| In general, data deformation can improve the detection quality of k-means and linear SVMs but not for the DBScan algorithm. [S2020, S2021] | **F**  | Data deformation can improve DBScan as well. DBScan uses distance metrics that can benefit from appropriate transformations.                                                                                           |
| In a worst case scenario, the runtime of DBScan is in O(#pts^3+dim). [S2019]                                                               | **F**  | The worst-case runtime of DBScan without spatial indexing is O(n^2), not O(n^{3+dim}).                                                                                                                                 |
| In a worst case scenario, the runtime of DBScan is in O(#pts^(3+dim)). [S2020]                                                             | **F**  | Same as above — worst case is O(n^2).                                                                                                                                                                                  |
| In a worst case scenario, the runtime of DBScan is in O(#pts \* dim). [S2021]                                                              | **F**  | The worst-case runtime is O(n^2), not O(n _ dim). O(n _ dim) is the cost of a single distance computation, not the full algorithm.                                                                                     |
| The Mahalanobis distance is a multivariate metric for calculating the distance between a point and a distribution. [W2022/23]              | **T**  | This is the correct definition of the Mahalanobis distance.                                                                                                                                                            |
| DBSCAN requires the user to specify the number of clusters in the data. [W2022/23]                                                         | **F**  | DBSCAN does NOT require specifying the number of clusters. It requires two parameters: epsilon (neighborhood radius) and minPts (minimum points for a core point). The number of clusters is determined automatically. |

---

### Q12.2: "Provide the algorithms for DBScan and linear SVM / k-means (including input parameters). In each of the resulting models, which points are predicted 'normal' / 'abnormal'?" [S2019 Task 7b (8pts), S2020 Task 8b (8pts), S2021 Task 10b (8pts)]

**A:** [DROPPED — not in current curriculum]

**DBSCAN Algorithm:**

Input: Dataset D, epsilon (neighborhood radius), minPts (minimum neighbors)

1. For each unvisited point p in D:
   a. Mark p as visited
   b. Find all points within epsilon distance of p (its epsilon-neighborhood)
   c. If the neighborhood contains >= minPts points, p is a CORE point:
   - Create a new cluster C, add p to C
   - For each point q in p's neighborhood: - If q is not visited, mark visited and find its epsilon-neighborhood - If q's neighborhood has >= minPts points, add those points to the expansion list - If q is not yet in any cluster, add q to C
     d. If the neighborhood contains < minPts points, label p as NOISE (for now; it may later be added to a cluster as a border point)

**Normal/Abnormal:** Points belonging to a cluster are predicted "normal." Points labeled as NOISE (not belonging to any cluster) are predicted "abnormal."

**k-Means Algorithm:**

Input: Dataset D, k (number of clusters)

1. Randomly initialize k cluster centroids
2. Repeat until convergence:
   a. Assignment step: Assign each point to the nearest centroid
   b. Update step: Recompute each centroid as the mean of all points assigned to it
3. Convergence = centroids no longer change (or change below threshold)

**Normal/Abnormal:** Points close to their assigned centroid (distance below a threshold) are predicted "normal." Points far from all centroids (distance above a threshold) are predicted "abnormal." The threshold is typically determined by domain knowledge or statistical analysis.

**Linear SVM Algorithm:**

Input: Labeled training data (normal and anomalous points)

1. Find the hyperplane w\*x + b = 0 that maximizes the margin between the two classes
2. The optimization: minimize ||w||^2 subject to y_i(w\*x_i + b) >= 1 for all training points
3. Support vectors are the training points closest to the hyperplane (on the margin boundary)

**Normal/Abnormal:** Points on one side of the hyperplane are "normal," points on the other side are "abnormal." The decision function is: if w\*x + b > 0, predict normal; otherwise, predict abnormal.

---

### Q12.3: "Give the algorithm for a Support Vector Machine (SVM). Clearly state inputs and outputs." [W2022/23 Task 14b (5pts)]

**A:** [DROPPED — not in current curriculum]

**Input:** Training dataset D = {(x_1, y_1), ..., (x_n, y_n)} where x_i are feature vectors and y_i in {-1, +1} are class labels.

**Algorithm:**

1. Solve the optimization problem: minimize (1/2)||w||^2 subject to y_i(w . x_i + b) >= 1 for all i
2. This finds the hyperplane w . x + b = 0 that maximizes the margin between the two classes
3. The support vectors are the training points that lie exactly on the margin boundary (y_i(w . x_i + b) = 1)

**Output:** Weight vector w and bias b defining the decision hyperplane. For a new point x, the classification is: sign(w . x + b). If positive, predict class +1 (normal); if negative, predict class -1 (anomalous).

---

### Q12.4: "Consider the dataset shown in the figure below. Explain if an SVM is capable of separating normal and anomalous data points. Describe a method you can utilize to make the dataset suitable for an SVM." [W2022/23 Task 14c (3pts)]

**A:** [DROPPED — not in current curriculum]

If the dataset is not linearly separable (as shown in the figure where normal and anomalous points are intermixed in a way that no straight line can separate them), a linear SVM cannot find a valid separating hyperplane.

To make the dataset suitable for an SVM, you can use the **kernel trick** — a data deformation technique that maps the data points into a higher-dimensional space where they become linearly separable. Common kernels include:

- **Polynomial kernel:** K(x, y) = (x . y + c)^d
- **RBF (Radial Basis Function) kernel:** K(x, y) = exp(-gamma \* ||x - y||^2)

After applying the kernel transformation, the SVM finds a linear hyperplane in the higher-dimensional space, which corresponds to a non-linear decision boundary in the original space.

---

## Topic 13: Statistics / Confusion Matrix (S2019, S2020, S2021, W2022/23) [DROPPED — not in current curriculum]

### Q13.1: Statistics True/False [S2019 Task 10 (5pts), S2020 Task 9 (4pts), S2021 Task 11 (4pts), W2022/23 Task 15a (4pts)]

**A:** [DROPPED — not in current curriculum]

| Statement                                                                                                                                                                                                                 | Answer                   | Justification                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Given a sequence of positive ratios, their average ratio is expressed by their geometric mean. [S2019]                                                                                                                    | **T**                    | The geometric mean is the appropriate measure for averaging ratios.                                                                                                     |
| The values of a nominal data type do not come with a natural ordering. [S2019]                                                                                                                                            | **T**                    | Nominal data has categories without inherent order (e.g., colors, names).                                                                                               |
| The Spearman Correlation Coefficient of two ordinal features F and G is defined as the correlation of the ranks of F respectively G. [S2019, S2020]                                                                       | **T**                    | This is the correct definition — Spearman's rho computes Pearson's correlation on rank-transformed data.                                                                |
| PCA is used to approximate the probability distributions of a family of features. [S2019, S2020]                                                                                                                          | **F**                    | PCA (Principal Component Analysis) is used to reduce dimensionality by finding directions of maximum variance, not to approximate probability distributions.            |
| In the t-test, we have to assume that the two given groups are approximately normally distributed. However, we do not need to assume that distributions of the two groups are approximately equal, up to a shift. [S2019] | **F**                    | The t-test does require both groups to be approximately normally distributed AND the variances to be approximately equal (or use Welch's t-test for unequal variances). |
| In the t-test, we have to assume that the two given groups are approximately normally distributed. [S2021, W2022/23]                                                                                                      | **T**                    | The t-test requires normality assumption.                                                                                                                               |
| The values of an ordinal data type do not come with a natural ordering. [S2020]                                                                                                                                           | **F**                    | Ordinal data DOES have a natural ordering (e.g., low/medium/high, education levels).                                                                                    |
| The values of an ordinal data type come with a natural ordering. [S2021]                                                                                                                                                  | **T**                    | Correct definition of ordinal data.                                                                                                                                     |
| In the U-test, we have to assume that the two given groups are approximately normally distributed. [S2020]                                                                                                                | **F**                    | The Mann-Whitney U-test is a non-parametric test that does NOT require normality assumption.                                                                            |
| The average positive ratio is the harmonic mean. [S2021]                                                                                                                                                                  | **F**                    | The average positive ratio is the geometric mean, not the harmonic mean. The harmonic mean is used for averaging rates.                                                 |
| The correlation measures the unnormalized variability of two random variables. [S2021]                                                                                                                                    | **F**                    | Correlation is NORMALIZED (ranges from -1 to +1). Covariance is the unnormalized measure.                                                                               |
| Given positive ratios x_1,...,x_n their harmonic mean is H(x_1,...,x_n) = ... [W2022/23]                                                                                                                                  | Depends on formula shown | The harmonic mean is n / (sum of 1/x_i). If the formula shown matches this, it is True.                                                                                 |
| The Spearman Correlation Coefficient computes the correlation of a nominal feature. [W2022/23]                                                                                                                            | **F**                    | Spearman's rho computes correlation of ordinal features (using ranks), not nominal features.                                                                            |
| The Principle Component Analysis embeds a given point cloud into a space of higher dimension. [W2022/23]                                                                                                                  | **F**                    | PCA reduces dimensionality (embeds into lower-dimensional space), not higher.                                                                                           |

---

### Q13.2: "Define the expected value E(X)." [S2019 Task 10a (2pts)]

**A:** [DROPPED — not in current curriculum]

The expected value of a discrete random variable X with probability measure p is defined as:

E(X) = sum over all omega in Omega of: X(omega) \* p(omega)

where Omega is the sample space, X(omega) is the value of the random variable at outcome omega, and p(omega) is the probability of that outcome.

---

### Q13.3: "Define the covariance Cov(X, Y) and show that Cov(lambda*X + mu, Y) = lambda*Cov(X, Y)." [S2019 Task 10b (3pts)]

**A:** [DROPPED — not in current curriculum]

The covariance of two random variables X and Y is defined as:

Cov(X, Y) = E[(X - E(X))(Y - E(Y))] = E(XY) - E(X)E(Y)

**Proof that Cov(lambda*X + mu, Y) = lambda*Cov(X, Y):**

Cov(lambda*X + mu, Y) = E[(lambda*X + mu) * Y] - E(lambda*X + mu) \* E(Y)

Using linearity of expectation:
= E(lambda*X*Y + mu*Y) - (lambda*E(X) + mu) * E(Y)
= lambda*E(XY) + mu*E(Y) - lambda*E(X)*E(Y) - mu*E(Y)
= lambda*E(XY) - lambda*E(X)_E(Y)
= lambda _ [E(XY) - E(X)*E(Y)]
= lambda \* Cov(X, Y)

---

### Q13.4: "Fill out the confusion matrix and compute the precision / accuracy of the virus scanner." [S2020 Task 9 (6pts), S2021 Task 11 (6pts), W2022/23 Task 15b (6pts)]

**A:** [DROPPED — not in current curriculum]

**Given (S2020):** Recall = TP/(TP+FN) = 100%, Specificity = TN/(TN+FP) = 99.9%, Total files = 10,030,000, Infected files = 30,000.

Not infected files = 10,030,000 - 30,000 = 10,000,000

From Recall = 100%: TP/(TP+FN) = 1, so FN = 0, therefore TP = 30,000.
From Specificity = 99.9%: TN/(TN+FP) = 0.999, so TN = 0.999 \* 10,000,000 = 9,990,000, and FP = 10,000,000 - 9,990,000 = 10,000.

|                     | File is infected | File is not infected |
| ------------------- | ---------------- | -------------------- |
| Reported by scanner | TP = 30,000      | FP = 10,000          |
| Not reported        | FN = 0           | TN = 9,990,000       |

**Precision** = TP/(TP+FP) = 30,000 / (30,000 + 10,000) = 30,000 / 40,000 = 0.75 = **75%**

**Given (S2021/W2022/23):** Same setup but Total files = 10,050,000, Infected = 50,000. Not infected = 10,000,000.

TP = 50,000 (from Recall = 100%), FN = 0
TN = 0.999 \* 10,000,000 = 9,990,000, FP = 10,000

**Accuracy** = (TP+TN) / Total = (50,000 + 9,990,000) / 10,050,000 = 10,040,000 / 10,050,000 = **99.9%** (approximately)

---

## Topic 14: Internet Routing (S2019, S2020, S2021) [DROPPED — not in current curriculum]

### Q14.1: "Calculate the Resilience / Impact regarding Prefix Hijacking of AS 64124." [S2019 Task 11 (10pts), S2020 Task 10 (10pts), S2021 Task 12 (10pts)]

**A:** [DROPPED — not in current curriculum]

These questions involve calculating metrics related to BGP prefix hijacking in a small Internet topology. The specific calculation depends on the network diagram provided.

**Resilience** measures the fraction of ASes that would still correctly route traffic to the victim AS even if a prefix hijacking occurs. It depends on the AS path lengths and the routing policies.

**Impact** measures the fraction of ASes that would be affected by a prefix hijacking attack on the victim AS. Impact = 1 - Resilience.

**General method:**

1. For each AS in the topology (excluding the victim and attacker), determine whether it would route traffic to the victim or to the attacker based on BGP path selection rules (shortest AS path, then local preference).
2. Count how many ASes correctly route to the victim (these are "resilient").
3. Resilience = (number of resilient ASes) / (total ASes - 1)
4. Impact = 1 - Resilience = (number of hijacked ASes) / (total ASes - 1)

The detailed calculation requires the specific network topology from the exam figure, which shows the AS relationships (customer-provider and peer links) and the AS path lengths.

---

## Topic 15: Certificate Revocation / PKI (S2019, S2020, S2021, W2022/23) [DROPPED — not in current curriculum]

### Q15.1: "The CA publishes CRLs. A complete CRL is always generated at the first day of the month. Specify the CRLs issued in [months] if the following certificates are revoked." [S2020 Task 6a (5pts), S2021 Task 8a (5pts)]

**A:** [DROPPED — not in current curriculum]

A Certificate Revocation List (CRL) contains the serial numbers of all certificates that have been revoked and are not yet expired. A complete CRL issued on a given date includes all certificates revoked up to that point that have not yet expired (their NotAfter date has not passed).

**Example (S2020):** Certificates issued by CA J, CRLs in April, May, June 2019:

Revocations: B on 03/05/2019, E on 05/05/2019, T on 14/05/2019, G on 24/05/2019, H on 03/06/2019.

**CRL April 2019 (issued 01/04/2019):** No certificates have been revoked yet. CRL = {} (empty).

**CRL May 2019 (issued 01/05/2019):** Still no revocations have occurred by 01/05. CRL = {} (empty). (B is revoked on 03/05, which is AFTER the CRL is generated on 01/05.)

**CRL June 2019 (issued 01/06/2019):** B, E, T, G have been revoked. Check expiration: Only include certificates whose NotAfter date is >= 01/06/2019 (not yet expired).

- B (NotAfter 31/12/2020): include serial 1
- E (NotAfter 31/12/2019): include serial 4
- T (NotAfter 31/12/2019): include serial 6
- G (NotAfter 31/12/2019): include serial 5
- S (NotAfter 31/12/2019): not revoked
  CRL June = {1, 4, 5, 6}

Note: The exact serial numbers and expiry dates must be read from the certificate table in the specific exam.

---

### Q15.2: "The CA introduces delta CRLs. The delta CRLs are issued twice a month, on the 10th and 20th. Write down the delta CRLs." [S2020 Task 6b (5pts), S2021 Task 8b (5pts)]

**A:** [DROPPED — not in current curriculum]

A delta CRL contains only the certificates that have been revoked since the last complete CRL was issued. It is an incremental update rather than a full list.

**Example (S2020):** Delta CRLs in May and June 2019:

**Delta CRL 10/05/2019:** Revocations since CRL of 01/05/2019: B (revoked 03/05), E (revoked 05/05). Both not expired. Delta = {1, 4}

**Delta CRL 20/05/2019:** Revocations since last delta (10/05): T (revoked 14/05). Delta = {6}

**Delta CRL 10/06/2019:** New base CRL was issued on 01/06. Revocations since 01/06: H (revoked 03/06). Delta = {3} (assuming H's serial is 3 and it's not expired)

**Delta CRL 20/06/2019:** Revocations since last delta (10/06): None new. Delta = {} (empty)

Note: Exact serial numbers depend on the certificate table in the specific exam.

---

### Q15.3: "Draw the full PKI hierarchies as trees. Insert a certificate such that P trusts in all certificates issued by F but does not trust in certificates issued by Q." [S2019 Task 6 (8+2 pts)]

**A:** [DROPPED — not in current curriculum]

A PKI hierarchy is represented as a tree where each certificate (issuer, subject) is a directed edge from the issuer to the subject. The root of each tree is the trust anchor. To build the hierarchy, start from the root (self-signed certificates where issuer = subject, like P->P) and add edges for each certificate.

To make P trust certificates issued by F without trusting Q: P must have a chain of certificates leading to F as a trusted CA, but no chain leading to Q. This is achieved by inserting a cross-certificate from P's trust hierarchy to F (e.g., adding a certificate (P, F) or a certificate from one of P's trusted CAs to F), ensuring there is no certificate chain from P's trust anchor to Q.

---

### Q15.4: "Determine the result of the verification on [date] based on the shell, hybrid and chain model." / "What is the reason for the distribution of certificate revocation lists?" [W2022/23 Task 9 (9+1 pts)]

**A:** [DROPPED — not in current curriculum]

The three PKI trust models differ in how they handle expired certificates in a chain:

**Shell model:** A certificate is valid only if it is valid at the time of verification. If any certificate in the chain has expired by the verification date, the entire chain is invalid.

**Chain model:** Each certificate in the chain only needs to have been valid at the time it was used to sign the next certificate in the chain. Expiration of an issuer's certificate does not invalidate certificates it previously signed.

**Hybrid model:** A compromise between shell and chain. The end-entity certificate must be valid at the time of verification, but CA certificates in the chain follow the chain model rules.

For the specific exam question, you check each certificate's NotBefore and NotAfter dates against the relevant dates (signing date for chain model, verification date for shell model) and determine validity under each model.

**Reason for CRL distribution:** CRLs are distributed so that relying parties can check whether a certificate has been revoked before the natural expiration date. Without CRLs, a compromised certificate would remain trusted until its NotAfter date, potentially allowing an attacker to use a stolen or compromised key for an extended period.

---

## Topic 16: SSE / STRIDE (W2023/24 only) [GUEST LECTURE — no slides available]

### Q16.1: "Define the following terms and write down the name of the affected CIA-property: Spoofing, Elevation of Privilege." [W2023/24 Ex.2a (4pts)]

**A:** [GUEST LECTURE — no slides available]

**Spoofing** is an attack where an attacker pretends to be someone or something else by falsifying identity information. For example, an attacker spoofs a legitimate user's credentials to gain unauthorized access. The affected CIA property is **Authenticity** (often grouped under **Integrity**, since the integrity of the identity claim is violated). Some frameworks also link it to **Confidentiality** (if the spoofing enables access to confidential data).

**Elevation of Privilege** is an attack where an attacker gains higher access rights than they are authorized to have. For example, a normal user exploits a vulnerability to gain administrator privileges. The affected CIA property is **Authorization/Integrity** (the integrity of the access control policy is violated). It can also affect **Confidentiality** if the elevated privileges grant access to sensitive data, and **Availability** if the attacker can disrupt services with elevated rights.

STRIDE is a threat modeling framework where each letter represents a threat category:

- **S**poofing (Authenticity)
- **T**ampering (Integrity)
- **R**epudiation (Non-repudiation)
- **I**nformation Disclosure (Confidentiality)
- **D**enial of Service (Availability)
- **E**levation of Privilege (Authorization)

---

### Q16.2: "Name one abuse and one misuse case for the following scenario [vending machine] and define the affected CIA-properties." [W2023/24 Ex.2b (6pts)]

**A:** [GUEST LECTURE — no slides available]

The scenario: A vending machine on campus where the purchase process is (1) hold prepaid card, (2) choose drink, (3) take drink, (4) payment debited from card.

**Abuse case (intentional malicious use):** An attacker clones or spoofs a prepaid card to obtain drinks without paying. This is an intentional attack that affects **Integrity** (the payment system's records are corrupted — the legitimate cardholder is charged instead of the attacker) and **Confidentiality** (the attacker obtained unauthorized access to the card's stored value). Another abuse case: An attacker tampers with the card reader to intercept card data from other users, affecting **Confidentiality**.

**Misuse case (unintentional/accidental misuse):** A user accidentally holds the wrong prepaid card (e.g., a friend's card) and unknowingly debits from the wrong account. This is an unintentional misuse that affects **Integrity** (the wrong account is debited) and potentially **Availability** (the friend's card balance is depleted without their knowledge). Another misuse case: The machine malfunctions and dispenses a drink without debiting the card, affecting **Integrity** of the financial records.

---

## Topic 17: Usable Security (W2023/24 only) [GUEST LECTURE — no slides available]

### Q17.1: "For the following survey questions, judge which are methodologically sound and which are problematic. If problematic, explain the problematic aspects." [W2023/24 Ex.3a (3pts)]

**A:** [GUEST LECTURE — no slides available]

**Question 1: "Do you use two-factor authentication for at least one of your online accounts?" (Yes/No/I don't know/I don't want to answer)**
This question is **methodologically sound**. It is a clear, unambiguous closed-ended question with appropriate response options including "I don't know" and "I don't want to answer" for respondents who are unsure or prefer not to disclose.

**Question 2: "How often do you use two-factor authentication per month?" (never / fewer than once / 1-5 / 5-10 / 10-15 / 15+)**
This question is **methodologically problematic**. The frequency ranges overlap (5-10 and 10-15 both include 5 and 10 respectively, though in this case the boundaries use "fewer than" phrasing). More importantly, the question is problematic because users typically do not count how many times they use 2FA per month — the number depends on how many services require it and how often they log in, making accurate self-reporting very difficult.

**Question 3: "How usable and secure do you think the process of two-factor authentication is?" (very usable and secure / moderately / neutral / somewhat / not)**
This question is **methodologically problematic** because it is a double-barreled question — it asks about two different concepts (usability AND security) in a single question. A respondent might find 2FA very secure but not very usable, or vice versa. These should be asked as two separate questions. Additionally, the response scale is inconsistent (mixing "very" with "somewhat" without clear gradation).

---

### Q17.2: Usable Security True/False [W2023/24 Ex.3b (7pts)]

**A:** [GUEST LECTURE — no slides available]

| Statement                                                                                                                                               | Answer | Justification                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Research in Usable Security and Privacy uses interview, survey, and experimental studies to investigate how human factors impact privacy and security.  | **T**  | This accurately describes the research methodology in the field.                                                                                                                         |
| Software users are the root cause of most IT security problems.                                                                                         | **F**  | While users make mistakes, the root cause is typically poor software design, inadequate security interfaces, and insufficiently secure defaults. Blaming users is an oversimplification. |
| Software developers are the root cause of most IT security problems.                                                                                    | **T**  | Most security vulnerabilities originate from design flaws, implementation bugs, and poor security practices by developers.                                                               |
| Most software developers are security experts.                                                                                                          | **F**  | The vast majority of software developers have limited security training and expertise. Security is a specialized domain.                                                                 |
| Informed consent means that study participants need to have sufficient information and understanding about a study, before deciding to take part in it. | **T**  | This is the correct definition of informed consent in research ethics.                                                                                                                   |
| In the SOUPS paper by Ion et al., security experts recommend using two-factor authentication more frequently than non-experts do.                       | **T**  | The Ion et al. study found that security experts were more likely to recommend and use 2FA compared to non-experts.                                                                      |
| In the SOUPS paper by Ion et al., security experts recommend using an antivirus program more frequently than non-experts do.                            | **F**  | The study found the opposite — non-experts recommended antivirus more frequently than experts, who instead prioritized practices like software updates and 2FA.                          |

---

## Topic 18: Domain-Specific Automated Software Testing (W2023/24 only) [GUEST LECTURE — no slides available]

### Q18.1: "Given the following parameters and test suite: Eliminate a row so that the remainder is still a 2-way test suite." [W2023/24 Ex.8a (4pts)]

**A:** [GUEST LECTURE — no slides available]

A 2-way (pairwise) test suite requires that for every pair of parameters, all possible value combinations appear in at least one test case. To eliminate a row, you must check that removing it does not lose any pair coverage.

Given: P1 in {0,1}, P2 in {0,1,2}, P3 in {0,1,2}

The total pairs to cover are:

- P1-P2: (0,0),(0,1),(0,2),(1,0),(1,1),(1,2) = 6 pairs
- P1-P3: (0,0),(0,1),(0,2),(1,0),(1,1),(1,2) = 6 pairs
- P2-P3: (0,0),(0,1),(0,2),(1,0),(1,1),(1,2),(2,0),(2,1),(2,2) = 9 pairs

To find which row can be removed: for each row in the test suite, check whether every pair it covers is also covered by at least one other row. If all of a row's pairs are redundantly covered, that row can be safely removed.

From the given test suite, systematically check each row for redundant coverage. The specific row that can be eliminated depends on the exact test suite provided. A row where every pairwise combination it contributes is already covered by other rows in the suite is the candidate for removal.

---

### Q18.2: "Define the property completeness for a test oracle." [W2023/24 Ex.8b (2pts)]

**A:** [GUEST LECTURE — no slides available]

A test oracle is said to be **complete** if it can detect ALL faults (bugs) in the system under test. Formally, whenever a fault exists in the implementation, the oracle will report a failure. In other words, a complete oracle has no false negatives — it never fails to detect an existing bug. Completeness means there are no faults that can escape detection by the oracle.

---

### Q18.3: "Consider differential testing of TLS servers which focuses only on the handshake process with a reduction function R(o) = raw bytes sent by the server, and assume the pool contains at least one perfect reference implementation. Prove that differential testing is not complete by giving a counter-example." [W2023/24 Ex.8c (4pts)]

**A:** [GUEST LECTURE — no slides available]

Differential testing works by running the same input on multiple implementations and comparing outputs. If outputs differ, a bug is detected. The reduction function R(o) = raw bytes sent by the server means we compare only the raw byte sequences of server responses.

**Counter-example proving incompleteness:** Consider a TLS server implementation that has a timing-based vulnerability (e.g., it leaks information through response timing differences based on the secret key, enabling a timing side-channel attack). This is a genuine security fault. However, the timing-vulnerable server sends exactly the same raw bytes as the reference implementation — the vulnerability manifests only in the time it takes to send the response, not in the content of the response.

Since the reduction function R(o) only examines the raw bytes sent and ignores timing, all implementations produce identical outputs under R. Differential testing would report no difference, failing to detect the timing vulnerability. This proves that differential testing with this reduction function is not complete, because there exists a fault that it cannot detect.

Alternative counter-example: A server that correctly handles the handshake but has a memory leak or use-after-free vulnerability during handshake processing. The raw bytes sent are correct, so differential testing reports no issue, but the vulnerability exists.

---

## Online Performance Test — Remaining Questions

### Online Test Q3: "Assign the following effects to the three given physical layer attack techniques." [Online Test Q3 (2pts)]

**A:** [DROPPED — not in current curriculum]

Physical layer attacks and their effects (wireless security):

- **Overshadowing:** Symbol Modification, Signal Strength Modification
- **Noise Jamming:** Attenuation, Annihilation
- **Preamble Corruption:** Bit Flipping, Amplification

(Exact mapping depends on the specific drag-and-drop assignments in the exam.)

---

### Online Test Q4: "Fill in the gaps about narrow-band jamming mitigation (FHSS and DSSS)." [Online Test Q4 (2pts)]

**A:** [DROPPED — not in current curriculum]

**FHSS** works by hopping between the transmission channels. The common secret needed is the hopping sequence. This transmission loses spectral efficiency by remaining silent on all other channels.

**DSSS** works by spreading the transmission onto a much wider frequency range but adjusting the signal power closer to noise level. The common secret needed is the spreading code. This transmission loses spectral efficiency by using less transmission power than available/allowed, resulting in less overall data bits being transmitted.

---

### Online Test Q5: "Perform a padding oracle attack on the cipher." [Online Test Q5 (4pts)]

**A:** This was a practical exercise requiring interaction with a web server. The approach follows the padding oracle attack mechanism described in Q1.5: systematically modify ciphertext bytes, observe the server's response (valid padding vs. invalid padding), and recover the plaintext byte by byte.

---

### Online Test Q8: "What are the key concepts of information security?" [Online Test Q8 (1pt)]

**A:** Confidentiality, Integrity, and Availability (CIA triad). See Q2.1 for full definitions.

---

_End of document. This compilation covers all unique questions from all 6 exam sources (5 written exams + 1 online test) across 18 topic areas._
