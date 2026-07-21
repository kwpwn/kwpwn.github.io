import type { HandbookConcept } from "./windows-security-handbook";
import { makeConcept } from "./windows-security-catalog-helpers";

const base = "https://splintersfury.github.io/KernelSight/mitigations";

export const mitigationConcepts: HandbookConcept[] = [
  makeConcept({
    slug: "dep-nx",
    title: "DEP and NX",
    group: "mitigations",
    level: "Foundation",
    summary:
      "Data Execution Prevention uses page permissions and the NX bit to prevent execution from mappings that are not explicitly executable.",
    model:
      "DEP removes the assumption that controlled data is executable code. It does not stop data-only corruption, valid code reuse, or an attacker who can legitimately create/change executable mappings under policy.",
    enables: [
      "Classify executable versus writable mappings",
      "Explain the shift to code reuse and data-only targets",
      "Audit W^X transitions",
    ],
    checks: [
      "Is the target mapping executable?",
      "Can protection be changed under current policy?",
      "Is a data-only target sufficient?",
      "Do ACG, HVCI, or code integrity further restrict executable memory?",
    ],
    sources: [
      {
        title: "Data Execution Prevention",
        href: "https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention",
        kind: "primary",
      },
    ],
    related: ["acg", "vbs-hvci", "kernel-rop"],
  }),
  makeConcept({
    slug: "kaslr",
    title: "KASLR",
    group: "mitigations",
    summary:
      "Kernel Address Space Layout Randomization changes the virtual locations of the kernel and other privileged images or regions to make hard-coded targets unreliable.",
    model:
      "KASLR raises the information requirement. The exploit must avoid absolute addresses, derive them from stable relationships, or obtain a disclosure valid for the current boot and address space.",
    enables: [
      "Reason about address uncertainty",
      "Separate pointer leaks from full arbitrary read",
      "Evaluate per-boot versus per-process knowledge",
    ],
    checks: [
      "Which base or object address is unknown?",
      "Does the leak reveal a current, canonical pointer?",
      "Can relative offsets remain stable across the exact image?",
      "Does VBS create a separate protected address domain?",
    ],
    source: `${base}/kaslr/`,
    related: ["kaslr-bypasses", "information-leak", "arbitrary-read"],
  }),
  makeConcept({
    slug: "kaslr-bypasses",
    title: "KASLR bypasses",
    group: "mitigations",
    summary:
      "A KASLR bypass recovers or avoids randomized kernel, driver, object, pool, or paging addresses through disclosure, side channels, deterministic relationships, or address-independent targets.",
    model:
      "Name exactly which address is recovered, with what lifetime and confidence. A kernel base leak may not reveal a pool object; a handle-table relationship may be build- and object-specific.",
    enables: [
      "Resolve code or data targets",
      "Build version-aware object chains",
      "Select address-independent data-only strategies",
    ],
    checks: [
      "What unknown becomes known?",
      "Is the value stale after reboot, process exit, or reallocation?",
      "Does the source expose cross-boundary data by design or by bug?",
      "Can the chain avoid the address entirely?",
    ],
    source: `${base}/kaslr-bypasses/`,
    related: ["kaslr", "information-leak", "kuser-shared-data"],
  }),
  makeConcept({
    slug: "smep-smap",
    title: "SMEP and SMAP",
    group: "mitigations",
    summary:
      "SMEP prevents supervisor execution from user pages; SMAP restricts supervisor access to user pages except through controlled access mechanisms.",
    model:
      "SMEP breaks direct jumps to user shellcode. SMAP breaks unguarded kernel reads/writes of user mappings. Neither inherently blocks kernel code reuse, data-only edits, or corruption of kernel mappings.",
    enables: [
      "Explain why user-mapped payloads fail",
      "Choose kernel-resident or data-only targets",
      "Audit safe user-buffer access",
    ],
    checks: [
      "Are SMEP and SMAP enabled by CPU and OS policy?",
      "Does the strategy execute from or access user pages?",
      "Can a legitimate copy/probe path perform the transfer?",
      "Do page-table changes remain viable under VBS/HVCI?",
    ],
    source: `${base}/smep-smap/`,
    related: ["pte-manipulation", "requestor-mode", "kernel-rop"],
  }),
  makeConcept({
    slug: "kcfg-kcet",
    title: "Kernel CFG and kernel CET",
    group: "mitigations",
    summary:
      "Kernel Control Flow Guard validates indirect-call targets, while kernel CET adds hardware-backed control-flow protections including shadow-stack enforcement on supported systems.",
    model:
      "kCFG restricts where indirect calls may land; kCET constrains return-address manipulation. They target different edges, so evaluate call-target validity, return behavior, arguments, and whether a data-only path avoids both.",
    enables: [
      "Evaluate controlled-call primitives",
      "Distinguish call-oriented and return-oriented constraints",
      "Prioritize data-only exploitation",
    ],
    checks: [
      "Is the call target in the valid CFG set?",
      "Does the chain corrupt returns or only data/calls?",
      "Is kernel CET active on this hardware/build?",
      "Can a legitimate dispatch or data-only target achieve the objective?",
    ],
    source: `${base}/kcfg-kcet/`,
    related: ["controlled-call-target", "kernel-rop", "vbs-hvci"],
  }),
  makeConcept({
    slug: "vbs-hvci",
    title: "VBS and HVCI",
    group: "mitigations",
    summary:
      "Virtualization-based security uses Hyper-V isolation and virtual trust levels; HVCI moves important code-integrity decisions and executable-page policy outside the normal kernel's direct control.",
    model:
      "VTL0 kernel compromise does not imply control of VTL1. Identify which data and policy are owned by the secure kernel, which mappings can become executable, and which targets remain writable from VTL0.",
    enables: [
      "Reason about virtual trust levels",
      "Evaluate executable mapping and driver-loading constraints",
      "Choose VTL0 data-only targets",
    ],
    checks: [
      "Is VBS running and is HVCI enabled?",
      "Which target is owned or protected by VTL1?",
      "Can the primitive only affect VTL0 page tables?",
      "Does the final action require loading unsigned code or only modifying existing data?",
    ],
    source: `${base}/vbs-hvci/`,
    related: ["kdp", "driver-signing-code-integrity", "pte-manipulation"],
    featured: true,
  }),
  makeConcept({
    slug: "kdp",
    title: "Kernel Data Protection",
    group: "mitigations",
    summary:
      "Kernel Data Protection allows selected kernel data to be protected through VBS-backed policy so ordinary VTL0 kernel writes cannot modify it after initialization.",
    model:
      "KDP is target-specific. It invalidates writes to registered static or dynamic protected regions but does not make all kernel data immutable or remove unrelated read/write targets.",
    enables: [
      "Explain protected data targets",
      "Separate KDP-protected and ordinary VTL0 state",
      "Re-evaluate data-only target selection",
    ],
    checks: [
      "Is the exact field inside a KDP-protected region?",
      "When is protection applied?",
      "Can the objective be reached through an unprotected consumer or object?",
      "Does the primitive cross into VTL1 at all?",
    ],
    source: `${base}/kdp/`,
    related: ["vbs-hvci", "token-manipulation", "kuser-shared-data"],
  }),
  makeConcept({
    slug: "pool-hardening",
    title: "Kernel pool hardening",
    group: "mitigations",
    summary:
      "Modern pool allocators add cookies, integrity checks, randomized behavior, segmentation, delayed reuse, metadata changes, and verifier options that reduce deterministic corruption and grooming.",
    model:
      "Hardening changes allocator assumptions. Measure bucket selection, locality, tags, headers, cookies, subsegments, reuse, quarantine, and object constructors on the target build instead of applying an old grooming recipe.",
    enables: [
      "Evaluate pool exploit reliability",
      "Choose compatible replacement objects",
      "Interpret verifier and allocator crashes",
    ],
    checks: [
      "Which allocator and bucket serve the object?",
      "Is metadata encoded or out of line?",
      "How deterministic is replacement under CPU locality?",
      "Can a semantic object field be targeted without touching protected metadata?",
    ],
    source: `${base}/pool-hardening/`,
    related: ["windows-kernel-pool", "pool-spray-feng-shui", "secure-pool"],
  }),
  makeConcept({
    slug: "secure-pool",
    title: "Secure Pool",
    group: "mitigations",
    summary:
      "Secure Pool protects selected allocations and metadata using VBS-backed mechanisms intended to detect or prevent unauthorized modification from the normal kernel.",
    model:
      "Like KDP, Secure Pool protects enrolled objects, not every allocation. Determine object eligibility, protection timing, update API, ownership, and whether the exploit can choose an ordinary replacement target.",
    enables: [
      "Identify protected heap objects",
      "Understand VBS-backed allocation integrity",
      "Adjust object-corruption target selection",
    ],
    checks: [
      "Is the allocation actually in Secure Pool?",
      "Which component may update it legitimately?",
      "Can the bug corrupt an unprotected reference or consumer instead?",
      "What telemetry or termination occurs on violation?",
    ],
    source: `${base}/secure-pool/`,
    related: ["pool-hardening", "vbs-hvci", "kdp"],
  }),
  makeConcept({
    slug: "acg",
    title: "Arbitrary Code Guard",
    group: "mitigations",
    summary:
      "Arbitrary Code Guard prevents a process from dynamically making new executable code, constraining JIT, injection, and runtime code-generation strategies.",
    model:
      "ACG is process policy. It blocks writable-to-executable transitions and certain executable mappings but does not automatically stop reuse of existing signed executable images or data-only manipulation.",
    enables: [
      "Audit process injection feasibility",
      "Distinguish code generation from image mapping",
      "Select data-only or trusted-code paths",
    ],
    checks: [
      "Is ACG enabled for the target process?",
      "Does the technique require making private memory executable?",
      "Can a broker create approved code?",
      "Do CIG, CFG, CET, and PPL add separate constraints?",
    ],
    source: `${base}/acg/`,
    related: ["dep-nx", "process-thread-token-surface", "kcfg-kcet"],
  }),
  makeConcept({
    slug: "driver-signing-code-integrity",
    title: "Driver signing and code integrity",
    group: "mitigations",
    summary:
      "Driver signing and code-integrity policy decide which kernel images may load; they do not authorize callers of an already loaded driver's device interface.",
    model:
      "Separate admission from use. Signing evaluates the driver image and policy at load time. Device DACLs, handle rights, gates, and handler validation govern who may exercise its privileged operations afterward.",
    enables: [
      "Avoid conflating signed with secure",
      "Understand vulnerable-driver block policy",
      "Map load-time and runtime boundaries separately",
    ],
    checks: [
      "Which signing policy and certificate path allow the image?",
      "Is the driver blocked by the vulnerable-driver list or WDAC policy?",
      "Who can install/start it?",
      "After load, who can open the device and invoke sensitive IOCTLs?",
    ],
    sources: [
      {
        title: "Driver signing policy",
        href: "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing-policy",
        kind: "primary",
      },
    ],
    related: ["byovd", "driver-gates-and-handshakes", "weak-device-dacl"],
  }),
  makeConcept({
    slug: "protected-process-light",
    title: "Protected Process Light",
    group: "mitigations",
    summary:
      "PPL restricts which processes and signers may obtain powerful handles or load code into protected processes according to protection type and signer level.",
    model:
      "PPL is an object-access and image-policy boundary, not a universal shield. Compare caller protection level, target signer, requested access, trusted service paths, kernel capabilities, and approved plugin/update mechanisms.",
    enables: [
      "Evaluate process-handle restrictions",
      "Reason about protected security services",
      "Separate admin rights from signer-level authority",
    ],
    checks: [
      "What is the target protection type/signer?",
      "Which access rights are filtered?",
      "Can approved plugins, services, or handles cross the boundary?",
      "Does the chain require kernel control or only a trusted broker?",
    ],
    sources: [
      {
        title: "Protected Services",
        href: "https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-",
        kind: "primary",
      },
    ],
    related: ["handle-acquisition", "security-policy-drivers", "vbs-hvci"],
  }),
];
