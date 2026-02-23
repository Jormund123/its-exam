# Phase 4: Remaining Topics + Mock Practice (~20 pts — MEDIUM)

**Slides covered:** 08 (Software Composition Analysis), 09 (Reproducible Builds)
**Exam evidence:** Neither topic has EVER appeared on a past exam. They may replace one or two of the guest-lecture topics (STRIDE, Usable Security, Domain-Specific Testing) that appeared on W2023/24 but have no slides.

---

## Topic 1: Software Composition Analysis (Slide 08)

> **NOT ASKED on past exam** — Never tested. Medium priority. These topics may appear as a 10-point question if the exam introduces new topics from the current slides.

### 1.1 Semantic Versioning (SemVer)

Semantic versioning uses the format **X.Y.Z** to systematically communicate the nature of changes in a software release.

- **X (Major version):** You increment this when you make incompatible API changes. Users upgrading across major versions should expect their code to break.
- **Y (Minor version):** You increment this when you add new functionality in a backward-compatible way. Existing code continues to work.
- **Z (Patch version):** You increment this when you make backward-compatible bug fixes only.

For example, `nginx/1.27.2` means major version 1, minor version 27, and patch version 2.

### 1.2 CVE and CVSS

A **CVE (Common Vulnerabilities and Exposures)** is a standardized identifier for a known software vulnerability. Each CVE entry specifies the affected software, the affected version range, and the vulnerability description.

**CVSS (Common Vulnerability Scoring System)** measures the severity of a CVE on a scale from 0 to 10. Multiple categories such as attack vector, attack complexity, privileges required, and impact feed into the final score. Multiple versions of the scoring system exist with different categories.

Be careful with CVEs: few actors control the ecosystem (MITRE, NVD) and their policies can lead to misleading scores. The CVE-2020-19909 example from the lecture showed a trivial curl integer overflow initially scored at 9.8 (critical), when the actual impact was negligible.

### 1.3 Banner Grabbing

Banner grabbing is the process of reading and evaluating version strings that software announces about itself.

**Advantages:** Banners are easy to fetch and can identify unknown software versions.
**Disadvantages:** Banners are easy to hide or spoof, they are unstructured, and there are no consistent locations across different software.

There are three main sources of banners:

**Output banners** come from software directly announcing its version. Command-line tools expose their version through flags like `--version`. Web servers announce their version in HTTP headers such as `Server: nginx/1.27.2`. Web applications embed version information in HTML meta tags like `<meta name="generator" content="WordPress 6.4.1" />`. HTML output also contains metadata like CDN script URLs with version numbers, plugin paths, and inline JavaScript data.

**Metafiles** are files served on a web server that are not required for functionality but left accessible through misconfiguration. Examples include `readme.txt` files (used to detect WordPress plugin versions), `composer.json` or `package.json` files (reveal all dependency versions), `.git/HEAD` files (reveal repository information and potentially credentials from history), and source maps (`.js.map` files that can expose filesystem paths and package versions through directory names like `.pnpm/uuid@3.4.0/`).

**Binaries** contain version strings embedded directly in the compiled binary. Running `strings` on a binary and filtering for version patterns like `[0-9]+\.[0-9]+\.[0-9]+` can extract version information.

### 1.4 Commercial SCA Tools

Several commercial and open-source tools perform SCA:

- **BuiltWith** is a closed-source product that analyzes technologies used on websites.
- **Shodan** is a closed-source search engine for internet-connected servers, suitable for finding IoT devices and other services.
- **Wappalyzer** is an open-source SaaS web technology scanner that works with an extensive set of regular expressions.
- **WPScan** is an open-source WordPress security scanner that retrieves versions through banner grabbing to search for known vulnerabilities.

### 1.5 JavaScript Bundle Analysis

Historically, JavaScript libraries were included as separate `<script>` tags with visible CDN URLs containing version numbers. Modern web development uses **bundlers** (such as Webpack, Esbuild, Parcel, and Browserify) that combine all modules into a single file, making version detection much harder.

**Bundling has four steps:**

1. **Build Module Graph:** Resolve all imports starting from an entry point to create a dependency graph of all modules.
2. **Tree Shaking:** Eliminate unused code through dead code elimination.
3. **Code Splitting:** Create multiple smaller bundles instead of one large file to reduce individual file sizes.
4. **Minification:** Reduce file size by shortening identifiers to single letters and removing whitespace.

**Three major challenges for SCA on JavaScript bundles:**

1. **Minification** makes identifiers meaningless because all variable names are shortened to single letters.
2. **Tree shaking** means packages may only be partially included, so the full library signature is absent.
3. **First-party code** is mixed in with library code and is difficult to distinguish.

**General approach for version detection:**

1. Build a reference database containing all versions of known packages.
2. Compare the similarity of each reference version with the target bundle.
3. The version with the highest similarity score is the detection result.

### 1.6 Abstract Syntax Trees (ASTs)

An AST is a tree representation of source code that captures its syntactic structure while ignoring formatting details like whitespace, comments, and semicolons.

**Primary use cases** for ASTs include compilers, interpreters, and static analysis tools.

**Advantages:** ASTs are easy to process programmatically, they are editable, they disregard irrelevant formatting, and nodes can carry annotations.

**Creating an AST** happens in two phases. First, **lexical analysis** converts a stream of characters into a stream of tokens. Then a **parser** constructs the AST from the token stream. For JavaScript, **ESTree** is the de-facto standard AST format, and **acorn** is the most appropriate parser implementation.

**AST structure rules:** The root node is always a `Program` node containing a sequence of statements. Siblings represent nodes at the same level. Nested structures are represented as children. Nodes are **contextless**, meaning they have no knowledge of their siblings or parents.

**Key ESTree node types:**

- **Leaf types:** `Identifier` (variable names with a `name` field), `Literal` (constant values with a `value` field), `RegExpLiteral` (regex patterns).
- **Control flow types:** `IfStatement` (has test, consequent, alternate), `ForStatement` (has init, test, update, body).
- **Expression types:** `BinaryExpression` (operator + left + right), `AssignmentExpression`, `MemberExpression` (object + property), `CallExpression` (callee + arguments).

### 1.7 AST Traversal and the Visitor Pattern

ASTs can be traversed using classical graph algorithms: **depth-first search (DFS)** or **breadth-first search (BFS)**.

The **visitor pattern** is the standard method for traversing an AST. As the tree is iterated (using an arbitrary strategy), a type-specific visitor method is called for each node encountered. For example, when a `VariableDeclaration` node is visited, the `VariableDeclaration` visitor method is invoked.

The `acorn-walk` library provides DFS-based traversal with two main modes:

- **`walk.simple`:** Iterates over the AST and executes all visitor methods for matching node types.
- **`walk.ancestor`:** Same as `walk.simple`, but also tracks the AST position so visitors can access all ancestor nodes. This is necessary for scope-aware analysis.

### 1.8 Webpack Detection via AST

To perform SCA on arbitrary JavaScript files, you first need to detect which bundler was used. Webpack uses a characteristic runtime function called `__webpack_require__` that resolves cross-compartment references.

Even after minification, the **structural pattern** (the AST shape) of this function remains detectable because minification changes identifier names but preserves the code structure. You detect Webpack by matching the fingerprint AST as a subtree in the bundle AST, comparing only node types and ignoring identifier names.

### 1.9 The Winnowing Algorithm for Similarity Comparison

The winnowing algorithm provides a way to compute rolling AST hashes for similarity comparison between code fragments.

**Step 1 — Extract k-grams:** Perform a DFS traversal of the AST and collect sequences of k consecutive node types. For example, with k=4, one k-gram might be `[Program, VariableDeclaration, VariableDeclarator, Identifier]`.

**Step 2 — Hash all k-grams:** Convert each k-gram into a numeric hash value.

**Step 3 — Select fingerprints using windows:** Slide a window of size w across the hash sequence and keep the smallest hash from each window position. This produces a compact set of fingerprints representing the code.

For example, with hashes `[32, 28, 49, 58, 5]` and window size w=2, the algorithm keeps `[28, 49, 5]` (the minimum from each window).

The resulting fingerprint set can then be compared against a reference database to identify which package and version is present in a bundle.

### Exam-Ready Checklist: SCA

- [ ] Define SemVer (X.Y.Z) and explain what each component means
- [ ] Define CVE and CVSS and their relationship
- [ ] Name three sources of banners (output, metafiles, binaries) with one example each
- [ ] Name the four bundling steps (module graph, tree shaking, code splitting, minification)
- [ ] Name three challenges for SCA on JavaScript bundles
- [ ] Define what an AST is and name its advantages
- [ ] Explain the visitor pattern for AST traversal
- [ ] Explain how Webpack detection works via AST matching (compare node types, ignore identifiers)
- [ ] Describe the three steps of the winnowing algorithm

---

## Topic 2: Reproducible Builds (Slide 09)

> **NOT ASKED on past exam** — Never tested. Medium priority. Could appear as a new 10-point question.

### 2.1 The Problem: Trusting Build Artifacts

When you install software, you typically download a pre-built binary artifact. If you want to verify security, you audit the source code. But there is a trust gap between the source code you audit and the binary you run — you have to trust that the binary was actually built from that source code. A malicious builder could inject backdoors during the build step without leaving any trace in the source code.

### 2.2 The Solution: Distributed Building

The idea behind reproducible builds is to distribute trust across multiple independent builders. Each builder compiles the same source code independently, and you compare their outputs. If one builder is malicious, their output will differ from all the honest builders. However, even benign builders do not always produce the same binary, which is the core challenge that reproducible builds try to solve.

### 2.3 Formal Definitions

**Reproducibility:** A triplet (input, function, output) is called reproducible if calling the function with the given input always yields the given output. The **input** may be any set of data or environment requirements that must be a specific value (anything not specified may be arbitrary). The **function** is any set of commands to be executed, such as a build script. The **output** is the set of artifacts that are created as a result and are considered "relevant" (other side effects may change).

Key advantages of this definition: it can be applied to any process, it does not require specific input/output types, any change in output means either the input or function changed (which is therefore suspicious), and it does not require the function to always be deterministic.

**Reproduced artifact:** An artifact is called "reproduced" if a third party has recreated it. This is weaker than reproducibility because it applies to a single artifact rather than a process, gives no guarantee that it can be done again, and the rebuilder might need to "magically" know certain build steps.

### 2.4 Four Levels of Binary Equivalence

This is the most important concept from this topic for exam purposes.

- **Level 1:** The whole files are **bit-by-bit identical**. You verify this by hashing both files with SHA-256 and comparing the hashes. Level 1 equality holds if and only if the hashes are equal. This is the strongest and most desirable level.
- **Level 2:** The **semantically relevant** parts of the files are bit-by-bit identical. You use a **normalization** process to bring semantically irrelevant differences (like timestamps, paths, or compiler version strings) into the same canonical form, then check Level 1 equivalence on the normalized files. Creating a correct normalizer is hard because it must only cover semantically irrelevant parts — false positives could mask security-relevant differences.
- **Level 3:** The files are **semantically equivalent** — they behave identically even though the bytes differ.
- **Level 4:** The files are **semantically similar** — they behave roughly the same way.

In practice, we usually aim for Level 1 or Level 2 equivalence. Level 1 is preferred because normalization is difficult and potentially security-relevant if done incorrectly.

### 2.5 Common Causes of Irreproducibility

These are the reasons why two honest builds of the same source code produce different binaries:

- **Timestamps** are the most common cause, with build timestamps embedded directly into binary artifacts.
- **Build path** differences arise because the absolute filesystem path where the build happens gets embedded into the binary.
- **Filesystem ordering** occurs because different systems may list files in different orders during the build.
- **Archive metadata** such as file permissions, ownership, and timestamps get stored in archive formats like tar or zip.
- **Unstable build dependencies** means dependencies may change over time if not pinned to exact versions.
- **Build ID** is a unique identifier generated per build.
- **Randomness** comes from build steps that use random values.
- **Encoding and locale** differences arise because different system locales produce different string representations.
- **Architecture information** and **user information** can also leak into build artifacts.

### 2.6 Two Types of Reproducibility Testing

**Remote artifact reproduction** is the process of testing whether a given artifact from a given ecosystem can be reproduced by a third party. Its goals are to confirm that a concrete existing artifact was not compromised, to show whether it is easy to reproduce locally, and to identify which parts of the artifact cannot be reproduced.

**Adversarial rebuilding** is the process of testing whether a given build process on a given input is reproducible under varying environments. Its goals are to show that the build process keeps creating the same output and to investigate which environment alterations (such as changing timestamps, paths, or locales) affect the output artifact.

### 2.7 Tools for Reproducibility Research

- **OSS Rebuild** performs remote artifact reproduction. It can test for Level 1 and Level 2 equivalence and publishes attestations about its results.
- **reprotest** performs adversarial rebuilding by building packages multiple times under deliberate environment modifications (changing timestamps, paths, locales, etc.).
- **diffoscope** creates recursive semantic diffs of archives, directories, and files. It has semantic support for many file types (JSON, tar.gz, ELF, etc.) and can show meaningful human-readable differences.
- **strip-nondeterminism** and **add-determinism** are stabilizers that remove non-deterministic elements from various file formats.

**Tool-to-testing-type mapping (from exercise):**
- OSS Rebuild → remote artifact reproduction
- reprotest → adversarial rebuilding
- diffoscope → both

### 2.8 Case Study: Python Cache File Poisoning

Python compiles `.py` source files into `.pyc` bytecode cache files stored in `__pycache__/` directories. If a cache file for a module exists, Python **prefers loading it over recompiling the source file**. This means a malicious package could ship tampered `.pyc` files that execute different code than what the source files show. Even if you audit all `.py` files, the package could still be malicious.

**Detection approach using reproducibility principles:** Download the package, compile your own cache files from the source, and compare them to the shipped cache files.

**Obstacle 1 — Metadata differences:** Cache files are serialized Code Objects containing fields like `co_filename` (the path where the file was originally compiled). These metadata fields differ between builds because the compilation paths are different. The solution is to use **Level 2 equivalence** — only compare `co_code` (the bytecode) and `co_consts` (the constants), recursively investigating nested code objects, while ignoring metadata fields.

**Obstacle 2 — Bytecode version differences:** Python's bytecode format changes across releases. Even releases sharing the same `MAGIC_NUMBER` bytecode version may emit slightly different bytecode. The solution is to compile with **all Python releases** that emit the same bytecode version and check if any of them produce a match.

### 2.9 Software Attestations

A **software attestation** is a cryptographically signed claim by a given identity about a given artifact. The three components are:

- **Identity:** Who signs the attestation (e.g., GitHub Actions).
- **Artifact:** What is attested (e.g., release 1.2.3 of some package).
- **Claim:** What is asserted (e.g., "built from commit XYZ using build script Y").

If you trust the signing entity and have verified the build inputs, you can trust the artifact.

### 2.10 Bootstrappable Builds

Bootstrappable builds start with a tiny, manually verifiable binary compiler. Using that small compiler, you compile the next compiler in the chain, and so on, until you have built the entire toolchain and final product. This means aside from the initial tiny binary, there is no dependence on pre-built binaries — everything in the software chain is verifiable from source code.

### Exam-Ready Checklist: Reproducible Builds

- [ ] Explain the trust problem between source code and build artifacts
- [ ] State the formal definition of reproducibility (triplet: input, function, output)
- [ ] Distinguish "reproducible" (property of a process) from "reproduced" (property of an artifact)
- [ ] Name and define all four levels of binary equivalence
- [ ] Explain normalization and why it enables Level 2 equivalence
- [ ] Name at least five common causes of irreproducibility
- [ ] Define remote artifact reproduction vs adversarial rebuilding
- [ ] Map tools to testing types: OSS Rebuild (remote), reprotest (adversarial), diffoscope (both)
- [ ] Explain the Python cache file poisoning attack and how reproducibility principles detect it
- [ ] State which level of binary equivalence was chosen in the Python case study (Level 2)
- [ ] Name the two obstacles in making Python cache files reproducible (metadata, bytecode versions)
- [ ] Define software attestation with its three components (identity, artifact, claim)
- [ ] Explain bootstrappable builds in one sentence

---

## Active Recall Quiz (Phase 4)

**Q1:** What are the three components of semantic versioning and what does each represent?

**A1:** X (Major) = incompatible API changes, Y (Minor) = backward-compatible new functionality, Z (Patch) = backward-compatible bug fixes.

**Q2:** Name the three sources of banners in banner grabbing.

**A2:** Output (command-line flags, HTTP headers, HTML meta tags), metafiles (readme files, package.json, .git/HEAD, source maps), and binaries (version strings extracted with `strings`).

**Q3:** What are the four steps of JavaScript bundling?

**A3:** (1) Build module graph from entry point, (2) tree shaking to eliminate unused code, (3) code splitting to create smaller bundles, (4) minification to reduce file size.

**Q4:** How does Webpack detection via AST work even after minification?

**A4:** Minification changes identifier names but preserves the code structure (the AST shape). You match the Webpack runtime fingerprint as a subtree in the bundle AST by comparing only node types, ignoring identifier names.

**Q5:** Describe the three steps of the winnowing algorithm.

**A5:** (1) Extract k-grams from a DFS traversal of the AST (sequences of k consecutive node types), (2) hash all k-grams into numeric values, (3) slide a window of size w across the hashes and keep the smallest hash from each window position.

**Q6:** State the formal definition of reproducibility.

**A6:** A triplet (input, function, output) is called reproducible if calling the function with the given input always yields the given output.

**Q7:** Name and define the four levels of binary equivalence.

**A7:** Level 1 = whole files are bit-by-bit identical (verify via hash comparison). Level 2 = semantically relevant parts are bit-by-bit identical (verify via normalization then hashing). Level 3 = files are semantically equivalent. Level 4 = files are semantically similar.

**Q8:** What is the difference between remote artifact reproduction and adversarial rebuilding?

**A8:** Remote artifact reproduction tests whether a specific existing artifact can be recreated by a third party (confirms artifact was not compromised). Adversarial rebuilding tests whether a build process produces the same output under varying environments (confirms the build process is deterministic).

**Q9:** In the Python cache file poisoning case study, which level of binary equivalence was chosen and why?

**A9:** Level 2 was chosen because cache files contain metadata like `co_filename` (the compilation path) that inherently differs between builds. By comparing only `co_code` and `co_consts`, the semantically relevant bytecode is compared while ignoring irrelevant metadata.

**Q10:** Define software attestation and name its three components.

**A10:** A software attestation is a cryptographically signed claim by a given identity about a given artifact. The three components are: identity (who signs), artifact (what is attested), and claim (what is asserted about the artifact).

---

## Mock Exam Strategy

Since both SCA and Reproducible Builds have **never appeared on any past exam**, here is the strategy:

1. **Most likely scenario:** The exam follows the W2023/24 format with 12 tasks at 10 points each. The three guest-lecture topics (SSE/STRIDE, Usable Security, Domain-Specific Testing) that occupied 30 points on W2023/24 may be replaced by SCA, Reproducible Builds, and/or Web Authentication.

2. **If SCA appears (10 pts):** Expect questions on banner grabbing (name sources + advantages/disadvantages), bundling steps, AST basics, and possibly the winnowing algorithm or Webpack detection.

3. **If Reproducible Builds appears (10 pts):** Expect the formal definition of reproducibility, the four levels of binary equivalence, tool-to-type mapping, and possibly the Python cache file case study.

4. **Time allocation on exam day:** Spend no more than 10 minutes per question. If you see an unfamiliar question, write the definition first (earns 2-3 points), then list components, then attempt the application.

5. **The guaranteed 90+ points** come from the CRITICAL and HIGH priority topics (Phases 1-3). These should be your primary focus during any remaining study time.
