# Phase 3: Specialized Topics (~30 pts — HIGH to MEDIUM)

**Slides covered:** 11 (Topological Data Analysis), 12 (Wireless Device Identification), 14 (Web Authentication Schemes)
**Exam evidence:** TDA appeared on W2023/24 (10pts). Device Identification appeared on BOTH W2022/23 and W2023/24 (10pts each). Web Authentication has never been tested directly but could appear as a new question.

---

## Topic 1: Topological Data Analysis (Slide 11)

> **ASKED ON EXAM** — W2023/24, Exercise 11 (2+4+2+2 = 10pts): *"Match persistence diagrams to point clouds; define homotopy equivalence and homeomorphism; determine if solid torus and hollow torus are homotopy equivalent; give example of homotopy equivalent but not homeomorphic."*

### 1.1 What is Topology?

Topology is the study of properties that are preserved under continuous deformations such as stretching, twisting, crumpling, and bending. The key rule is that you cannot close or open holes, tear, glue, or pass the object through itself. In other words, topology studies properties that remain invariant as long as the connectivity of the space does not change.

Geometric properties are defined by shape, size, and position. Topological properties are defined by connectivity and continuity. A coffee mug and a donut are topologically equivalent because both have exactly one hole, even though their geometric shapes are completely different.

### 1.2 Metric Spaces

A metric space is a set X together with a distance function d: X × X → R that satisfies four axioms:

1. **Non-negativity:** d(x,y) ≥ 0
2. **Identity of indiscernibles:** d(x,y) = 0 if and only if x = y
3. **Symmetry:** d(x,y) = d(y,x)
4. **Triangle inequality:** d(x,z) ≤ d(x,y) + d(y,z)

In practice, TDA typically works with point clouds in Euclidean space where the distance function is the standard Euclidean distance. Every metric space is automatically a topological space, but not every topological space is a metric space.

An **invariant** is a quantity that remains unchanged under a certain class of transformations. For example, the number of holes in a shape is a topological invariant because it does not change under continuous deformations.

### 1.3 Simplicial Complexes

A simplicial complex K is a finite collection of simplices (points, edges, triangles, tetrahedra, and their higher-dimensional analogues) that defines a triangulation of a topological space. It must satisfy two rules:

1. Every face of each simplex in K must also be in K. If you include a triangle {a,b,c}, you must also include all its edges {a,b}, {a,c}, {b,c} and all its vertices {a}, {b}, {c}.
2. The intersection of any two simplices in K must be either empty or a face of both.

An **abstract simplicial complex** is the combinatorial version of this concept. It consists of a set of vertices and a collection of subsets (the simplices) such that if a set is in the collection, all of its subsets must also be included. For example, the abstract simplicial complex K = {∅, {0}, {1}, {2}, {0,1}, {0,2}, {1,2}, {0,1,2}} represents a filled triangle with three vertices, three edges, and one 2-simplex (the filled face).

The process of converting an abstract simplicial complex into a geometric one is called **geometric realization**, where each simplex is associated with the convex hull of its vertices in a geometric space.

### 1.4 Vietoris-Rips Complex

The Vietoris-Rips complex is the standard method for constructing a simplicial complex from a point cloud in a metric space. For a metric space X and a diameter threshold ε, the Vietoris-Rips complex is defined as:

**VR_ε(X) = { σ ⊆ X | for all x,y ∈ σ: d(x,y) ≤ ε }**

This means a subset σ of points forms a simplex if and only if every pair of points in σ is within distance ε of each other. As ε increases from 0 to infinity, more edges, triangles, and higher-dimensional simplices appear, progressively revealing the topological structure of the underlying data.

### 1.5 Homology Groups

Homology is a mathematical tool that associates a sequence of algebraic groups H₀(X), H₁(X), H₂(X), ... to a topological space X. Each group Hd(X) gives a measure of the number of "d-dimensional holes" in X. These groups are algebraic invariants of the topological space, meaning they depend only on the topological properties, not on the specific geometric shape.

| Homology Group | What It Counts | Intuition |
|----------------|---------------|-----------|
| H₀ | Connected components | How many separate pieces the space has |
| H₁ | 1-dimensional holes (loops) | Holes you could thread a string through |
| H₂ | 2-dimensional voids (cavities) | Enclosed hollow spaces inside the object |

Comparing the homology groups of two spaces allows us to determine whether they could be topologically equivalent. If their homology groups differ, they cannot be topologically equivalent.

### 1.6 Key Shapes and Their Homology (EXAM CRITICAL)

Understanding the homology of standard shapes is essential for matching persistence diagrams to point clouds on the exam.

| Shape | H₀ | H₁ | H₂ | Explanation |
|-------|----|----|-----|-------------|
| **2D Ring (circle, S¹)** | 1 | 1 | 0 | One connected component. One loop (the ring itself). No enclosed voids. |
| **Hollow Sphere (S²)** | 1 | 0 | 1 | One connected component. No loops (any loop on the surface can be continuously contracted to a point). One enclosed void (the hollow interior). |
| **Filled Torus (solid torus, S¹ × D²)** | 1 | 1 | 0 | One connected component. One loop (the central circle going through the donut ring). No voids because the interior is filled solid. |
| **Hollow Torus (T² = S¹ × S¹)** | 1 | 2 | 1 | One connected component. **Two** independent loops (one going around the ring, one going through the tube). One enclosed void (the hollow interior of the tube). |

The hollow torus has two independent loops because there are two topologically distinct ways to trace a path that cannot be continuously deformed into a point: going around the "ring" of the donut, or going through the "tube" of the donut.

### 1.7 Filtration and Persistent Homology

A **filtration** is a nested sequence of simplicial complexes K₀ ⊆ K₁ ⊆ K₂ ⊆ ... ⊆ Kₙ. For Vietoris-Rips complexes, the filtration is obtained by gradually increasing the radius ε from 0 to infinity. At each step, new simplices may appear, causing topological features to be "born" (a new connected component, loop, or void appears) or to "die" (a feature merges with another or fills in).

**Persistent homology** tracks which homological features are born and which die at each step of the filtration. The persistence of a feature (the length of the interval between its birth and death) is interpreted as a measure of its importance. Long-lived features represent genuine topological structure in the data, while short-lived features are typically noise caused by sampling.

### 1.8 Persistence Diagrams and Barcodes

A **persistence diagram** is a scatter plot where each topological feature is represented as a point with coordinates (birth, death). The birth value is the ε at which the feature first appears, and the death value is the ε at which it disappears. Points far from the diagonal (long persistence = large death − birth) represent significant topological features, while points near the diagonal represent noise.

A **barcode** is an equivalent visualization where each feature is shown as a horizontal bar extending from its birth time to its death time. Longer bars indicate more persistent (and therefore more significant) features.

### 1.9 Matching Persistence Diagrams to Shapes (Exam Pattern)

When matching a persistence diagram to a point cloud shape, count the number of persistent features (points far from the diagonal) in each dimension:

| Shape | Persistent H₁ features | Persistent H₂ features | Key distinguishing trait |
|-------|------------------------|------------------------|-------------------------|
| **2D Ring** | 1 | 0 | Only H₁ features, no H₂ |
| **Filled Torus** | 1 | 0 | Same as ring in terms of persistent features, but H₁ born at different scale |
| **Hollow Sphere** | 0 | 1 | No H₁, only H₂ (unique!) |
| **Hollow Torus** | 2 | 1 | Most features: 2 in H₁ and 1 in H₂ (unique!) |

The hollow sphere is the easiest to identify because it is the only shape with no persistent H₁ features but one persistent H₂ feature. The hollow torus is also easy because it has the most features. The 2D ring and filled torus both have one persistent H₁ feature and no H₂, so they must be distinguished by scale or context.

### 1.10 Persistence Distances

The two standard distance metrics for comparing persistence diagrams are:

**Bottleneck distance** w∞(X,Y): finds the optimal matching η between points of diagrams X and Y that minimizes the maximum distance between any matched pair. It measures the worst-case displacement between the two diagrams.

**Wasserstein distance** wₚ(X,Y): similar to the bottleneck distance, but uses the Lᵖ norm to aggregate all matched-pair distances rather than taking only the maximum. It measures the total (or average) displacement between the two diagrams.

### 1.11 Homeomorphism (EXAM DEFINITION)

> **ASKED ON EXAM** — W2023/24 (11b, 4pts)

Two topological spaces X and Y are **homeomorphic** if there exists a continuous bijection f: X → Y whose inverse f⁻¹: Y → X is also continuous. Such a function f is called a homeomorphism. Homeomorphic spaces are essentially "the same" from a topological point of view — every topological property of X is shared by Y and vice versa. Informally, a homeomorphism is a reversible rubber-sheet deformation that preserves all topological structure.

### 1.12 Homotopy Equivalence (EXAM DEFINITION)

> **ASKED ON EXAM** — W2023/24 (11b, 4pts)

Two topological spaces X and Y are **homotopy equivalent** if there exist continuous maps f: X → Y and g: Y → X such that the composition g∘f is homotopic to the identity map on X, and the composition f∘g is homotopic to the identity map on Y. Two maps are homotopic if one can be continuously deformed into the other.

Homotopy equivalence is a weaker condition than homeomorphism. Every homeomorphism implies homotopy equivalence (because a homeomorphism is a special case), but the converse is not true. Homotopy equivalence allows spaces of different dimensions to be "equivalent" — for example, a solid disk can be continuously contracted to a single point.

### 1.13 Solid Torus vs Hollow Torus

> **ASKED ON EXAM** — W2023/24 (11c, 2pts): *"Are a solid torus and a hollow torus homotopy equivalent?"*

A solid torus (S¹ × D²) and a hollow torus (T² = S¹ × S¹) are **NOT homotopy equivalent**. The reason is that the solid torus is homotopy equivalent to a circle (S¹), because the filled disk cross-section can be continuously contracted to a point, leaving only the central circle. This gives the solid torus H₁ = Z (one independent loop). The hollow torus, on the other hand, has H₁ = Z² (two independent loops). Since homology is a homotopy invariant (meaning homotopy equivalent spaces must have the same homology groups), and the homology groups of the two spaces differ, they cannot be homotopy equivalent.

### 1.14 Homotopy Equivalent but Not Homeomorphic (EXAM EXAMPLE)

> **ASKED ON EXAM** — W2023/24 (11d, 2pts)

**Example:** A solid disk D² and a single point {p} are homotopy equivalent because the disk can be continuously contracted to its center point (a deformation retraction). However, they are not homeomorphic because there is no continuous bijection between them — the disk is a two-dimensional space with infinitely many points, while a point is zero-dimensional.

**Alternative example:** A solid torus (S¹ × D²) and a circle (S¹). The solid torus deformation retracts onto its central circle, making them homotopy equivalent. But they are not homeomorphic because one is three-dimensional and the other is one-dimensional (they cannot be put in continuous bijection).

### Exam-Ready Checklist: TDA

- [ ] I can define a metric space with all four axioms
- [ ] I can explain what a simplicial complex is and give the two rules it must satisfy
- [ ] I can define the Vietoris-Rips complex formula
- [ ] I can state what H₀, H₁, and H₂ count (components, loops, voids)
- [ ] I know the homology of 2D ring, hollow sphere, filled torus, and hollow torus
- [ ] I can read a persistence diagram and identify persistent features by dimension
- [ ] I can match persistence diagrams to shapes based on feature counts per dimension
- [ ] I can define homeomorphism (continuous bijection with continuous inverse)
- [ ] I can define homotopy equivalence (continuous maps f and g with g∘f ~ id and f∘g ~ id)
- [ ] I can prove that solid torus and hollow torus are NOT homotopy equivalent (different H₁)
- [ ] I can give an example of homotopy equivalent but not homeomorphic spaces (disk and point, or solid torus and circle)

---

## Topic 2: Wireless Device Identification (Slide 12)

> **ASKED ON EXAM** — W2022/23, Task 3 (3+3+4 pts) AND W2023/24, Exercise 9 (3+3+4 pts): *"Defensive actor example; direct/indirect DID characteristics; passive vs active DI scenario."* This topic appeared on BOTH recent exams with nearly identical question structure.

### 2.1 What is Device Identification?

Device identification (DI) is the ability to uniquely identify a user or device based on a unique ID such as a MAC address, IMEI, or MEID. The lecture focuses mostly on wireless environments, where devices transmit signals over a shared medium and their communications can be observed by any receiver in range.

### 2.2 DI Goals

The goals of device identification range from broad categories to specific individual devices:

- **Device types:** Distinguishing a TV from a phone from a laptop from a smart lamp.
- **Device manufacturers:** Distinguishing Samsung from Google from Cisco.
- **Device models:** Distinguishing a Galaxy S22 from a Galaxy A13.
- **Device properties:** Identifying supported protocols, features, or screen sizes.
- **Unique devices in a network:** Distinguishing your specific phone from another phone of the same model.

### 2.3 RF Fingerprinting

RF fingerprinting identifies devices based on the radio frequency characteristics of their transmissions. Imperfections introduced during the manufacturing process of wireless chips lead to slight deviations in frequency, transmission power, clock skew, and other signal properties. These deviations create a hardware-specific "fingerprint" that is unique to each individual device and very difficult to forge because it originates from physical manufacturing variations.

### 2.4 Defensive and Offensive Perspectives

> **ASKED ON EXAM** — W2022/23 (3a), W2023/24 (9a): *"Give an example for why utilizing device identification techniques can benefit a defensive actor."*

**Defensive perspective (network authority):**
- Law enforcement agencies can maintain regulatory control by identifying illegal transmitters.
- Mobile operators can identify cloned cell phones attempting to use stolen identities.
- Network administrators can identify and track problematic or unauthorized hosts.
- Intrusion detection systems can detect identity spoofing by comparing RF fingerprints against a database of known authorized devices.

**Exam-ready defensive example:** A corporate network administrator maintains an RF fingerprint database of all authorized wireless devices. When an unknown device attempts to connect using a spoofed MAC address to impersonate an authorized device, the intrusion detection system compares the device's RF fingerprint against the database. Because the physical RF fingerprint does not match the stored fingerprint for that MAC address, the system flags the device as an intruder and blocks the connection.

**Offensive perspective (attacker):**
- Identifying valuable targets (e.g., executive laptops) to break into a network.
- Privacy violation through unauthorized tracking of individuals via their devices.
- Protocol compromise, where it matters that a third party cannot distinguish which device sent a certain packet.

### 2.5 Direct DID vs Indirect DID

> **ASKED ON EXAM** — W2022/23 (3b): indirect DID; W2023/24 (9b): direct DID

**Direct DID** are device identifying data that qualify for device identification by themselves. A single direct DID is sufficient on its own to identify or uniquely distinguish a device.

Examples of direct DID:
- **MAC address:** A globally unique hardware identifier assigned to the wireless chip by the manufacturer. It directly and uniquely identifies a specific device because no two devices should share the same global MAC address.
- **IMEI (International Mobile Equipment Identity):** A unique number assigned to every mobile device. It is transmitted in cellular protocol headers and directly identifies the specific physical device.
- **WPS UUID:** A universally unique identifier used in Wi-Fi Protected Setup that directly identifies a specific device.

These qualify as direct DID because each one is globally unique by design and is directly tied to a specific physical device, making identification possible from that single data point alone.

**Indirect DID** are device identifying data that by themselves are not sufficient for unique identification, but can provide additional information to narrow down or support the identification process.

Examples of indirect DID:
- **Signal strength (RSS):** Varies with distance and environment and can hint at a device's location, but many different devices at the same distance would produce similar RSS values.
- **Clock skew / frequency offset:** Slightly different per device due to manufacturing variations in oscillators, but not precise enough alone to uniquely identify a device.
- **Scrambler seed sequence:** Reveals information about the device's LFSR state, which can help track it across randomized MACs, but is not unique enough on its own.
- **Modulation errors:** Device-specific but require a trained classifier and many observations to be useful for identification.

**Exam-ready indirect DID answer (W2022/23 3b):** A collectible characteristic that qualifies as indirect DID is the clock skew (frequency offset) of a wireless transmission. It qualifies as indirect DID because while different devices exhibit slightly different clock skew values due to manufacturing variations in their oscillators, the clock skew alone is not precise enough to uniquely identify a specific device — it can only help narrow down the set of candidate devices when combined with other identifying information.

### 2.6 Passive Device Identification

Passive device identification means only observing the communication traffic of the target device without generating any traffic yourself. The fingerprinter listens in on packets sent over the shared wireless medium and extracts DID from what it observes. Passive DI is dependent on the communication state the target device is in, because connected devices tend to send more traffic and expose more information.

**Signal-based passive techniques (do not use packet content):**
- **Statistical approaches on RF features:** Analyzing complex IQ signals (e.g., ZigBee preambles) using statistical classification and regression models.
- **Transient-based approaches:** Analyzing the signal ramp-up from channel noise to full power before a new transmission. The time and shape of this transient signal are hardware-specific.
- **Modulation-based approaches:** Extracting modulation errors such as frequency offset, I/Q origin offset, magnitude/phase offset, and SYNC correlation. Different devices produce slightly different errors that can be used for classification.
- **RSS-based approaches:** Differentiating transmitting devices via received signal strength and related metrics.
- **Permutation entropy:** Measuring the complexity of a chaotic time series derived from the RF signal.

**Packet-content-based passive techniques:**
- **Behavioral analysis:** Statistical analysis of the rate at which 802.11 data link layer frames are transmitted, which varies depending on the specific driver used by the device.
- **Scrambler seed analysis:** The scrambler encodes a packet before transmitting using a pseudo-random bitstring generated by an LFSR. By observing the Scrambler Init field, the fingerprinter can predict the scrambling sequence for the next packet, linking packets sent by the same device even across MAC randomization.
- **Identifier extraction:** Reading device identifiers (MAC address, IMEI, WPS UUID) directly from unencrypted packet headers.
- **Information Element (IE) fingerprinting:** Analyzing the combination, order, and values of optional Wi-Fi Information Elements in probe requests. The Vanhoef technique concatenates IE tags and values into a single fingerprint string that can de-anonymize devices even when MAC randomization is used.

### 2.7 Active Device Identification

Active device identification means generating purpose-built traffic to interact with the target device and then observing its response. The fingerprinter actively engages the target device to make it send packets containing useful identifying information. Active DI is more flexible but is also easier for network authorities to detect.

**AP Impersonation attacks (active DI techniques):**
- **Karma Attack:** Listens to directed probe requests from the target device, then impersonates an access point using an SSID that was observed in those requests. The target device may automatically connect, revealing its global MAC address and additional information.
- **Mana Attack:** Reconstructs the Preferred Network Lists (PNLs) of nearby devices by observing their probe requests before engaging in active communication.
- **Known Beacon Attack:** Attempts to brute-force the target device's PNL by broadcasting beacon frames with commonly used SSIDs (like "eduroam", "Starbucks", etc.), hoping the device will respond.
- **WiFi-based IMSI Collector:** Uses a rogue access point to trick mobile devices into revealing their IMSI.
- **Hotspot 2.0 rogue AP:** Exploits the Hotspot 2.0 auto-connection mechanism.

### 2.8 Passive vs Active DI: Key Differences

| Aspect | Passive DI | Active DI |
|--------|-----------|-----------|
| Traffic generation | None — observation only | Sends stimulus packets to the target |
| Detectability | Very hard to detect by the target or network authority | Easier to detect because the fingerprinter transmits |
| Flexibility | Limited to what the device voluntarily sends | Can trigger specific responses from the target |
| Risk to attacker | Minimal — the attacker remains invisible | May reveal the attacker's presence and location |
| Application layer FP | Can be circumvented by changing app parameters | More flexible, explores different scenarios |
| Physical layer FP | Difficult to compromise due to inherent physical properties | — |

### 2.9 Passive DI When Communication is Encrypted

> **ASKED ON EXAM** — W2022/23, Task 3c (4pts): *"Communication is completely encrypted, no access to header or content. Name a passive DI technique."*

When all communication is encrypted (including headers and payload), packet-content-based techniques cannot be used. However, signal-based passive techniques still work because they analyze the physical properties of the transmitted RF signal rather than the data content.

**Suitable technique:** Transient-based identification or modulation-based identification. These techniques analyze the RF signal characteristics — such as the transient signal shape during power ramp-up, or modulation errors like frequency offset and I/Q origin offset — without needing to read any packet content. They work because the physical characteristics of the transmission are determined by the hardware (the wireless chip's manufacturing imperfections), not by the encrypted data being sent.

**Drawbacks:** These techniques require specialized hardware (an SDR or high-resolution receiver) to capture raw RF signals with sufficient precision. They also require a pre-trained classifier that has previously observed the target device's signals, meaning they cannot identify a device that has never been seen before. Environmental factors such as distance, interference, and multipath propagation can degrade accuracy, and the technique may not work reliably in all conditions.

### 2.10 Active DI Can Be Harmful to the Attacker

> **ASKED ON EXAM** — W2023/24, Exercise 9c (4pts): *"Scenario where active DI is harmful to the attacker but passive DI works."*

**Scenario:** An attacker wants to identify and track a specific device within a corporate network that is monitored by a wireless intrusion detection system (WIDS). The network security team actively monitors for rogue access points and unusual wireless traffic patterns.

**Why active DI is harmful:** Active device identification requires the attacker to transmit packets — for example, broadcasting beacon frames in a Known Beacon Attack or impersonating an access point in a Karma Attack. The WIDS would detect these unusual transmissions originating from an unrecognized source, immediately alerting the security team. The attacker's physical location could be triangulated based on the signal strength of their transmissions, leading to their discovery.

**Why passive DI works:** Passive device identification only requires the attacker to listen to existing wireless traffic without ever transmitting a packet. Signal-based techniques such as transient analysis or modulation-based identification can be performed purely through observation. Since the attacker never transmits, the WIDS has no way to detect the fingerprinter's presence, and the attacker remains completely invisible to the monitored network.

### 2.11 MAC Randomization

MAC randomization is a privacy countermeasure where devices use randomly generated MAC addresses instead of their real (global) hardware MAC address. This prevents easy tracking of devices based on their MAC address. Key facts:

- MAC randomization is **not part of any Wi-Fi specification** — there is no standard for when, where, or how to use it.
- The **universal/local bit** (the second-to-last bit of the first MAC byte) indicates whether the MAC is global (bit = 0) or local/randomized (bit = 1).
- **Apple devices** randomize all 47 bits of the MAC address, making it impossible to determine the original vendor.
- Many **Android devices** only randomize the NIC portion (last 3 bytes), leaving the OUI (first 3 bytes / vendor prefix) intact, which still reveals the manufacturer.
- MAC randomization is typically used for **probe requests** (network discovery) where the device does not need to be addressable. When the device wants to actually connect to a network, it can fall back to its global MAC or use a consistent "session MAC" that does not change during the connection.

### 2.12 Information Elements (IEs)

Information Elements are Wi-Fi-specific fields in management frames (particularly probe requests). Some IEs are mandatory for the protocol to function, while many are optional and advertise the device's capabilities. The specific combination, order, and values of IEs create a fingerprint that can de-anonymize devices even when MAC randomization is used, because different device types and driver versions include different sets of optional IEs. The Vanhoef fingerprinting technique extracts IE tags and their values, concatenates them into a single fingerprint string, and uses string comparison to filter packets from the same device.

### Exam-Ready Checklist: Device Identification

- [ ] I can give a defensive actor example with specific use of identifying data (e.g., RF fingerprint database for intrusion detection)
- [ ] I can name and explain at least 2 direct DIDs (MAC address, IMEI) and why they qualify
- [ ] I can name and explain at least 2 indirect DIDs (clock skew, scrambler seed) and why they qualify
- [ ] I can explain the difference between passive DI (observation only) and active DI (generating traffic)
- [ ] I can name a passive DI technique that works on fully encrypted communication (transient-based or modulation-based) and explain its drawbacks
- [ ] I can describe a scenario where active DI harms the attacker but passive DI does not
- [ ] I can explain MAC randomization, the universal/local bit, and Apple vs Android differences
- [ ] I can name the three AP impersonation attacks: Karma, Mana, Known Beacon

---

## Topic 3: Web Authentication Schemes (Slide 14)

> **NOT ASKED on past exam** — This is a new topic by guest lecturer Melina Hoffmann. It has never been tested directly, but could appear as a new question. Treat it as medium priority.

### 3.1 Motivation

Traditional username-and-password authentication has several weaknesses: users must remember credentials for every service, passwords may be weak or reused across services, users must enter personal data multiple times, and online services may use weak security measures when storing credentials. Modern web authentication schemes address these problems by using public-key cryptography, hardware tokens, or adaptive risk assessment.

### 3.2 German eID (Online-Ausweis)

The German electronic identity system was introduced in 2010. It uses a chip embedded in German identity documents (identity card, passport, residence permit) that stores the holder's personal data analogous to the printed information on the document. The eID can be used for online identification and authentication that is linked to a state-issued and verified offline identity.

**Components:**
- **Identity document:** Stores personal data (name, date of birth, expiry date, nationality) and eID-specific cryptographic keys on its chip.
- **Card reader:** A dedicated reader device or an NFC-compliant smartphone.
- **6-digit PIN:** Known only to the cardholder, used to authorize each authentication.
- **eID client:** Software on the local device (e.g., AusweisApp by Governikus) that manages the authentication process on the client side.
- **eID service:** The online service that uses eID authentication. If it wants to read personal data beyond pseudonyms, it must obtain official infrastructure and an authorization certificate through a certification process.
- **eID server:** The infrastructure component that handles secure communication between the eID client, the identity document chip, and the eID service.

### 3.3 eID Online Authentication Process

The online authentication process has five steps:

1. The user visits the eID service's website and is prompted for online authentication.
2. The eID service sends an authentication request to the eID server and activates the eID client on the user's device.
3. The **General Authentication Procedure** runs between the eID server, the eID client, and the chip on the identity document. This procedure consists of three sub-protocols:
   - **PACE (Password Authenticated Connection Establishment):** Verifies that the user has knowledge of the PIN corresponding to the presented eID card. This is a mutual authentication between the eID client and the chip.
   - **EACv2 (Extended Access Control Version 2):**
     - **Terminal Authentication v2:** The eID service proves its authenticity and access rights by presenting its technical authorization certificate. This certificate specifies which data fields the service is allowed to request.
     - **Passive Authentication:** A digital signature from the card manufacturer authenticates the data stored on the chip, and the chip's static public key is verified.
     - **Chip Authentication v2:** A Diffie-Hellman-based protocol that further authenticates the chip by verifying that it contains the private key corresponding to the verified public key from the previous step.
4. The eID server transmits the authentication result and the requested personal data to the eID service.
5. The eID service checks the response and, if satisfactory, grants access to the user.

### 3.4 eID Pseudonyms and Revocation

The eID system can generate **service-specific pseudonyms** that allow a service to recognize and re-identify a customer without learning any of their actual personal data. This protects user privacy while still enabling personalized services.

**Revocation** is necessary when an identity document is lost or stolen. The system uses **service-specific revocation lists** rather than a single global list to preserve pseudonymity. If a global list used card serial numbers or linked all service-specific pseudonyms to one entry, the pseudonymity guarantees would be broken. The revocation process involves revocation keys (stored on the chip), revocation passwords (sent to the cardholder with the PIN letter), and revocation codes (hashes of personal data and the revocation password).

### 3.5 eID Limitations

The eID system is linked to state-issued documents and identities, involves a complex setup including a formal certification process, and depends on a complex infrastructure of trusted components (eID servers, authorization PKI, revocation service). It is considered quite secure as of today, although not entirely without risks or attack vectors (e.g., the sPACE attack, CVE-2024-23674).

### 3.6 FIDO2

FIDO2 is an authentication standard specified by the W3C and the FIDO Alliance (Fast Identity Online). Its goal is to replace password-based schemes or augment them with public-key-cryptography-based authentication that is more secure, simpler to use, and simpler to deploy.

**Components:**
- **Authenticator:** A hardware-based token that generates and stores private-public key pairs. This can be built into the client device (e.g., a fingerprint reader on a laptop), or be an external hardware key (e.g., YubiKey), or software-based.
- **Relying Party:** The service using FIDO2 authentication, consisting of a web application and a FIDO2 server.
- **Client:** The bridge between the authenticator and the relying party, typically the user's web browser or OS subsystem.
- **CTAP (Client to Authenticator Protocol):** Handles communication between the client and the authenticator.
- **WebAuthn:** Handles communication between the client and the relying party via JavaScript APIs.

### 3.7 FIDO2 Registration and Authentication

**Registration (creating a new credential):**
1. The relying party server sends a challenge, user info, and relying party info to the client.
2. The client forwards the relying party ID, user info, and a hash of the client data to the authenticator.
3. The authenticator performs user verification (e.g., fingerprint scan or PIN), generates a new public-private key pair, and creates an attestation object.
4. The new public key, credential ID, and attestation are sent back through the client to the relying party server.
5. The server validates the attestation and stores the public key for future authentication.

**Authentication (proving identity):**
1. The relying party server sends a challenge to the client.
2. The client forwards the relying party ID and client data hash to the authenticator.
3. The authenticator performs user verification and creates a cryptographic assertion (a signature over the challenge using the stored private key).
4. The authenticator data and signature are sent back to the relying party server.
5. The server validates the signature using the stored public key.

### 3.8 FIDO2 Limitations

In the basic version, credentials are tied to a single authenticator device (if you lose the device, you lose access). The setup is more complex than simple password-based schemes. It requires additional background infrastructure (FIDO2 server). Some attacks are possible, such as man-in-the-middle during registration. FIDO2 is used by numerous companies including Discord, Dropbox, eBay, Facebook, GitHub, and the University of Bonn.

### 3.9 Browser Fingerprinting

A browser fingerprint is a set of information related to a user's device — from the hardware to the operating system to the browser and its configuration. Browser fingerprinting collects this information through a web browser to build a profile that can distinguish one device from another.

**Key attributes used for fingerprinting:**
- **HTTP User-Agent header:** A request header that reveals the application, operating system, vendor, and version of the requesting browser. Originally meant to prevent incompatibility problems.
- **Content language** as specified in HTTP headers.
- **List of installed plugins.**
- **Timezone, screen resolution, and color depth.**
- **Use of an ad blocker.**
- **Canvas fingerprinting:** The Canvas API draws graphics that are influenced by the OS, browser version, graphics card, and installed fonts. Different devices render the same canvas drawing slightly differently. The fingerprinter renders an invisible picture in the user's browser and collects the characteristic rendering as part of the fingerprint.

**Limitations:** Browser fingerprinting is not a precise authentication method. Its uniqueness varies significantly depending on the method and definition used. It is primarily used for fraud detection and prevention by searching for anomalies in user behavior patterns rather than as a standalone authentication mechanism.

### 3.10 Risk-Based Authentication (RBA)

RBA is an adaptive security measure that strengthens password-based authentication by monitoring additional features during the login process to assess the risk of identity theft. If the calculated risk exceeds a certain threshold, additional authentication factors are required.

**Attacker model:** The attacker knows the correct credentials or can guess them with a low number of tries.

**Login process with RBA:**
1. During password entry, additional features are monitored in the background (IP address, user agent string, language, display resolution, login time).
2. From these features, the service calculates a risk score.
3. Depending on the risk score:
   - **Low risk:** No additional action required.
   - **Medium risk:** Additional authentication factor required (e.g., email verification code, SMS code).
   - **High risk:** Access is blocked entirely.

**Study findings (Wiefling et al. 2019):** Investigated 8 online services (Amazon, Facebook, GOG.com, Google, iCloud, LinkedIn, Steam, Twitch). Used parameters, risk thresholds, and triggered actions varied significantly between services. All discovered feature sets contained IP address. All discovered RBA schemes used verification codes as the additional authentication factor. Google was the most sophisticated: changing any single feature triggered an email security alert, and strong IP address variation triggered an additional authentication factor.

**Limitations:** RBA is not a standardized authentication scheme. Its security depends entirely on the quality of the fingerprinting and authentication methods chosen by the service. It risks inconveniencing legitimate users who deviate from their usual behavioral patterns (e.g., traveling to a new country). It may also add privacy risks by collecting and storing user behavioral data.

### Exam-Ready Checklist: Web Authentication

- [ ] I can list the 5 components of the German eID system (document, reader, PIN, eID client, eID service/server)
- [ ] I can describe the 5 steps of the eID online authentication process
- [ ] I can explain PACE, Terminal Authentication, Passive Authentication, and Chip Authentication
- [ ] I can explain why the eID uses service-specific revocation lists instead of a global list
- [ ] I can describe FIDO2's components (authenticator, relying party, client, CTAP, WebAuthn)
- [ ] I can outline the FIDO2 registration and authentication flows
- [ ] I can list at least 5 attributes used in browser fingerprinting
- [ ] I can explain canvas fingerprinting (render invisible image, collect device-specific rendering)
- [ ] I can describe RBA's login process (monitor features, calculate risk score, escalate based on threshold)
- [ ] I can compare the suitability of eID, FIDO2, browser FP, and RBA for different scenarios

---

## Active Recall Quiz

Test yourself on the key exam concepts from Phase 3. Try to answer each question before reading the answer.

### Q1: Homology Groups
**Question:** What do H₀, H₁, and H₂ count? What are the homology groups of a hollow torus?

**Answer:** H₀ counts connected components, H₁ counts 1-dimensional holes (loops), and H₂ counts 2-dimensional voids (cavities). The hollow torus T² has H₀ = 1 (one connected component), H₁ = 2 (two independent loops — one around the ring, one through the tube), and H₂ = 1 (one enclosed void).

### Q2: Homeomorphism vs Homotopy Equivalence
**Question:** Define homeomorphism and homotopy equivalence. Which one is the stronger condition?

**Answer:** A homeomorphism between X and Y is a continuous bijection f: X → Y whose inverse f⁻¹ is also continuous. Homotopy equivalence means there exist continuous maps f: X → Y and g: Y → X such that g∘f is homotopic to id_X and f∘g is homotopic to id_Y. Homeomorphism is the stronger condition — every homeomorphism implies homotopy equivalence, but not vice versa.

### Q3: Solid vs Hollow Torus
**Question:** Are a solid torus and a hollow torus homotopy equivalent? Justify your answer.

**Answer:** No, they are not homotopy equivalent. The solid torus is homotopy equivalent to a circle (S¹), which has H₁ = Z (one independent loop). The hollow torus has H₁ = Z² (two independent loops). Since homology is a homotopy invariant, spaces with different homology groups cannot be homotopy equivalent.

### Q4: Homotopy Equivalent but Not Homeomorphic
**Question:** Give an example of two spaces that are homotopy equivalent but not homeomorphic.

**Answer:** A solid disk D² and a single point are homotopy equivalent because the disk can be continuously contracted to its center. They are not homeomorphic because there is no continuous bijection between a two-dimensional space and a zero-dimensional space. Another example: a solid torus and a circle.

### Q5: Defensive Actor Example
**Question:** Give an example of how device identification benefits a defensive actor.

**Answer:** A network administrator maintains an RF fingerprint database of all authorized wireless devices. When an unknown device connects using a spoofed MAC address to impersonate an authorized device, the intrusion detection system compares the device's RF fingerprint against the database. The physical fingerprint does not match, so the system flags the device as an intruder.

### Q6: Direct vs Indirect DID
**Question:** Name one direct DID and one indirect DID, and explain why each qualifies.

**Answer:** A direct DID is the MAC address — it is globally unique and assigned to a specific wireless chip, so it qualifies for device identification by itself. An indirect DID is clock skew (frequency offset) — while different devices exhibit slightly different values due to manufacturing variations, it is not precise enough alone to uniquely identify a device; it can only narrow down candidates when combined with other information.

### Q7: Passive DI on Encrypted Communication
**Question:** If all communication is encrypted (including headers), what passive DI technique can you still use? What are its drawbacks?

**Answer:** Transient-based or modulation-based identification, which analyze the physical RF signal properties rather than packet content. Drawbacks: requires specialized hardware (SDR), requires a pre-trained classifier for the target device, environmental conditions can degrade accuracy, and it cannot identify a device it has never observed before.

### Q8: Active DI Harmful to Attacker
**Question:** Describe a scenario where active DI harms the attacker but passive DI does not.

**Answer:** In a corporate network monitored by a wireless IDS, active DI requires the attacker to transmit packets (e.g., Known Beacon Attack). The IDS detects these transmissions and alerts security, potentially revealing the attacker's location. Passive DI only requires listening to existing traffic without transmitting, so the IDS cannot detect the fingerprinter's presence.

### Q9: FIDO2 Components
**Question:** Name the four main components of FIDO2 and the two communication protocols.

**Answer:** The four components are: (1) Authenticator (hardware token generating key pairs), (2) Relying Party (the service using FIDO2), (3) Client (bridge between authenticator and relying party, typically the browser), and (4) the user. The two protocols are CTAP (Client to Authenticator Protocol) and WebAuthn (between client and relying party).

### Q10: eID Authentication Steps
**Question:** Name the three sub-protocols of the General Authentication Procedure in the German eID system.

**Answer:** (1) PACE (Password Authenticated Connection Establishment) — verifies the user knows the PIN. (2) Terminal Authentication v2 (part of EACv2) — proves the eID service's authenticity and access rights. (3) Chip Authentication v2 (part of EACv2) — Diffie-Hellman-based protocol authenticating the chip by verifying it holds the corresponding private key. There is also Passive Authentication (verifying the chip's stored data using a manufacturer signature) between Terminal Auth and Chip Auth.
