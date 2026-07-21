import type { HandbookConcept } from "./windows-security-handbook";

interface PrimitiveSeed {
  slug: string;
  title: string;
  summary: string;
  model: string;
  enables: string[];
  constraints: string[];
  composition: string;
  source?: string;
  related?: string[];
  aliases?: string[];
  level?: HandbookConcept["level"];
}

const kernelSight = "https://splintersfury.github.io/KernelSight/primitives/";

function primitive(seed: PrimitiveSeed): HandbookConcept {
  return {
    slug: seed.slug,
    title: seed.title,
    group: "primitives",
    level: seed.level ?? "Advanced",
    summary: seed.summary,
    mentalModel: seed.model,
    whyItMatters:
      "Exploitability depends on the exact capability, not the bug-class label. Record what is controlled, what remains fixed, how often the operation can be repeated, and which security boundary the final composition crosses.",
    enables: seed.enables,
    mechanics: [
      "Start from the concrete vulnerable operation and identify the data or object that becomes attacker-controlled.",
      `Measure the primitive: ${seed.constraints.join("; ")}.`,
      seed.composition,
      "Verify the result on the exact Windows build, record active mitigations, and restore or dispose of modified state in the lab.",
    ],
    questions: [
      "What can be selected independently: target, value, size, offset, timing, process, or object?",
      ...seed.constraints.map(
        (constraint) => `Have you measured ${constraint.toLowerCase()}?`,
      ),
      "Which leak, allocator behavior, privileged consumer, or mitigation bypass is still required?",
    ],
    sources: [
      {
        title: `${seed.title} — KernelSight`,
        href: seed.source ?? kernelSight,
        kind: "reference",
      },
    ],
    related: seed.related ?? [],
    aliases: seed.aliases,
  };
}

export const primitiveConcepts: HandbookConcept[] = [
  primitive({
    slug: "arbitrary-read",
    title: "Arbitrary memory read",
    summary:
      "Read bytes from an attacker-selected virtual address in a privileged address space or process context.",
    model:
      "The attacker chooses where data comes from; the implementation chooses how much, in which address space, and how faults are handled. A read is often a resolver for a later write rather than the final impact.",
    enables: [
      "Defeat KASLR",
      "Recover object or token addresses",
      "Read secrets or construct a data-only chain",
    ],
    constraints: [
      "address range",
      "maximum width",
      "alignment",
      "fault behavior",
      "repeatability",
    ],
    composition:
      "Resolve stable objects or secrets, then pair the disclosure with a write, impersonation, mapping, or control-flow capability.",
    related: ["information-leak", "arbitrary-write", "kaslr-bypasses"],
  }),
  primitive({
    slug: "information-leak",
    title: "Information disclosure",
    summary:
      "Reveal a pointer, cookie, pool header, token field, uninitialized bytes, or other value that removes uncertainty from a later stage.",
    model:
      "A leak is useful only relative to a question: which unknown does it answer? Name the randomized base, object identity, secret, layout, or state transition it resolves.",
    enables: [
      "KASLR bypass",
      "Heap-layout recovery",
      "Secret or cross-boundary data disclosure",
    ],
    constraints: [
      "leaked value",
      "freshness",
      "scope",
      "noise and parsing",
      "stability across boots",
    ],
    composition:
      "Convert the leaked value into a concrete address, object identity, or secret and show the next operation that consumes it.",
    related: ["uninitialized-memory", "out-of-bounds-read", "kaslr"],
  }),
  primitive({
    slug: "arbitrary-write",
    title: "Arbitrary memory write",
    summary:
      "Write attacker-influenced bytes to an attacker-selected virtual address, with strength determined by width, value control, and repeatability.",
    model:
      "Target control and value control are separate axes. A full eight-byte write, partial overwrite, zero write, increment, and bit set all reach different viable targets.",
    enables: [
      "Data-only privilege edits",
      "Object or pointer corruption",
      "Page-table or control-flow manipulation",
    ],
    constraints: [
      "target selection",
      "value control",
      "write width",
      "atomicity",
      "old-value knowledge",
      "repeatability",
    ],
    composition:
      "Choose a target whose required mutation matches the write constraints and remains viable under kCFG, kCET, VBS, HVCI, and KDP.",
    related: ["write-what-where", "constrained-write", "token-manipulation"],
  }),
  primitive({
    slug: "write-what-where",
    title: "Write-what-where",
    summary:
      "A strong arbitrary-write form in which the attacker independently controls both the destination address and the value copied there.",
    model:
      "Treat 'what' and 'where' as independently validated inputs. Pointer provenance, copy length, alignment, address-space context, and fault handling still decide reliability.",
    enables: [
      "Replace a pointer or access mask",
      "Edit token state",
      "Modify a page-table entry or dispatch target",
    ],
    constraints: [
      "independence of source and destination",
      "copy length",
      "alignment",
      "address-space context",
      "fault handling",
    ],
    composition:
      "Resolve a stable target, preserve surrounding fields, perform the smallest safe mutation, and verify that a mitigation does not reject the resulting state.",
    source: `${kernelSight}arw/write-what-where/`,
    related: ["arbitrary-write", "pte-manipulation", "controlled-call-target"],
  }),
  primitive({
    slug: "constrained-write",
    title: "Constrained write",
    summary:
      "Change memory with a restricted value or shape, such as zeroing, a constant, a partial-pointer overwrite, increment/decrement, or a single-bit transition.",
    model:
      "Do not ask whether the write is 'arbitrary.' Ask which target fields accept exactly the mutation supplied without destroying adjacent state.",
    enables: [
      "Clear a mode or protection bit",
      "Adjust a reference or access count",
      "Redirect within a nearby address range",
    ],
    constraints: [
      "fixed value or operation",
      "affected bits",
      "carry or borrow",
      "write width",
      "target precondition",
    ],
    composition:
      "Search for semantically tolerant targets—flags, counters, low pointer bytes, access masks, lengths, or reference state—then prove the transition is stable.",
    related: [
      "arbitrary-increment-decrement",
      "bit-manipulation",
      "arbitrary-write",
    ],
  }),
  primitive({
    slug: "arbitrary-increment-decrement",
    title: "Arbitrary increment or decrement",
    summary:
      "Add or subtract a fixed unit at a chosen address, often through reference-count, length, or atomic-operation misuse.",
    model:
      "The target value is not directly chosen. The attacker controls direction, address, repetition, and timing, while carries, saturation, underflow, and concurrency shape the outcome.",
    enables: [
      "Reference-count manipulation",
      "Flag or length transitions",
      "Repeated construction of a desired numeric value",
    ],
    constraints: [
      "increment size",
      "operation count",
      "atomicity",
      "carry and underflow",
      "concurrent mutation",
    ],
    composition:
      "Select a counter, flags word, reference field, or pointer byte whose reachable states produce a safe and useful semantic change.",
    source: `${kernelSight}arw/arb-increment-decrement/`,
    related: [
      "constrained-write",
      "bit-manipulation",
      "reference-counting-bugs",
    ],
  }),
  primitive({
    slug: "bit-manipulation",
    title: "Bit-manipulation primitive",
    summary:
      "Set, clear, toggle, or test selected bits while preserving the rest of a field.",
    model:
      "Bit primitives are semantic writes: their strength comes from matching a meaningful flag transition rather than from controlling a full machine word.",
    enables: [
      "Change token or object flags",
      "Modify access or protection state",
      "Preserve adjacent packed fields",
    ],
    constraints: [
      "bit direction",
      "available mask",
      "atomicity",
      "initial value",
      "repeatability",
    ],
    composition:
      "Map candidate flags for the exact build, verify no protected invariant detects the change, and choose a reversible transition where possible.",
    source: `${kernelSight}exploitation/bit-manipulation/`,
    related: ["constrained-write", "token-manipulation", "pte-manipulation"],
  }),
  primitive({
    slug: "controlled-dereference",
    title: "Controlled pointer dereference",
    summary:
      "Cause privileged code to read from or write through an attacker-chosen pointer without necessarily controlling the transferred value.",
    model:
      "Separate pointer control from data control. The surrounding instruction decides direction, size, offset, value, exception behavior, and whether the pointer is probed as user data.",
    enables: [
      "Read or corrupt a chosen field",
      "Trigger an object or callback lookup",
      "Upgrade a type confusion into a stronger primitive",
    ],
    constraints: [
      "instruction semantics",
      "fixed offset",
      "access direction",
      "value provenance",
      "probe mode and exceptions",
    ],
    composition:
      "Recover the exact instruction and register state, then select a target compatible with its fixed width, offset, and value source.",
    related: ["type-confusion", "requestor-mode", "controlled-call-target"],
  }),
  primitive({
    slug: "controlled-call-target",
    title: "Controlled call target",
    summary:
      "Redirect an indirect call, callback, dispatch pointer, vtable slot, or return path to an attacker-influenced target.",
    model:
      "Control flow is constrained by executable mappings, calling convention, register state, kCFG valid-target sets, shadow stacks, and VBS/HVCI policy.",
    enables: [
      "Invoke a valid kernel function",
      "Build a code-reuse chain",
      "Reach a data-only gadget or dispatch path",
    ],
    constraints: [
      "valid target set",
      "arguments and register state",
      "stack control",
      "executable mapping",
      "kCFG and kCET",
    ],
    composition:
      "Prefer a valid-call-target or data-only strategy compatible with active mitigations; record why direct shellcode or a traditional ROP chain is or is not possible.",
    related: ["kcfg-kcet", "kernel-rop", "arbitrary-write"],
  }),
  primitive({
    slug: "direct-ioctl-read-write",
    title: "Direct IOCTL read/write",
    summary:
      "A driver intentionally exposes read, write, mapping, register, or hardware operations through an IOCTL and fails to constrain their target or caller sufficiently.",
    model:
      "The interface itself may be working as designed. The security defect is the gap between who can reach it and the authority of the operation it performs.",
    enables: [
      "Kernel or physical memory access",
      "MSR, port, PCI, or MMIO access",
      "BYOVD composition",
    ],
    constraints: [
      "device DACL",
      "IOCTL access bits",
      "gate or handshake",
      "address allowlist",
      "operation size and alignment",
    ],
    composition:
      "First pass device authorization and protocol state, then translate the exposed backend into a stable virtual-memory or data-only capability.",
    source: `${kernelSight}arw/direct-ioctl-rw/`,
    related: ["ioctl-handlers", "driver-gates-and-handshakes", "byovd"],
  }),
  primitive({
    slug: "dma-mmio-access",
    title: "DMA and MMIO access",
    summary:
      "Influence device memory transactions or map hardware register windows that can affect memory, firmware, isolation, or privileged device behavior.",
    model:
      "DMA is a device-originated memory operation; MMIO is CPU access to device registers through a mapped address range. IOMMU policy, BAR validation, cache type, ownership, and lifetime are part of the boundary.",
    enables: [
      "Read or write physical memory through a device",
      "Program privileged hardware state",
      "Reach firmware or peer-device surfaces",
    ],
    constraints: [
      "IOMMU translation",
      "physical range",
      "BAR or register allowlist",
      "cache attributes",
      "device state and concurrency",
    ],
    composition:
      "Prove which device owns the range and translate hardware-level access into a deterministic OS object, mapping, or security-state change.",
    source: `${kernelSight}arw/dma-mmio/`,
    related: ["physical-memory", "performance-and-gpu-drivers", "vbs-hvci"],
  }),
  primitive({
    slug: "mdl-mapping",
    title: "MDL mapping primitive",
    summary:
      "Abuse a memory descriptor list to lock, describe, or map pages into a context where the attacker gains unintended access.",
    model:
      "An MDL describes physical pages backing a virtual range; it does not own the memory. Track who built it, whether the range was probed and locked, where it is mapped, and when it is unlocked.",
    enables: [
      "Map kernel or physical pages",
      "Create a user-accessible view",
      "Convert a pointer bug into repeated access",
    ],
    constraints: [
      "page ownership",
      "probe and lock state",
      "mapping protection",
      "cache type",
      "lifetime and cleanup",
    ],
    composition:
      "Stabilize the MDL and mapping lifetime, then use the mapped view for a bounded read/write or data-only modification.",
    source: `${kernelSight}arw/mdl-mapping/`,
    related: [
      "physical-memory",
      "pte-manipulation",
      "ioctl-encoding-and-buffering",
    ],
  }),
  primitive({
    slug: "pipe-attribute-primitives",
    title: "Named-pipe attribute primitives",
    summary:
      "Use internal named-pipe attribute objects and queue state as controllable pool objects for disclosure, replacement, or read/write construction.",
    model:
      "The pipe is an allocator and object-shaping interface. The exploit depends on object size, attribute layout, queue ownership, server/client lifetime, and the read-back path—not merely on creating many pipes.",
    enables: [
      "Pool shaping",
      "Object replacement after UAF",
      "Read-back of corrupted or fake metadata",
    ],
    constraints: [
      "allocation size class",
      "attribute layout",
      "pipe-end ownership",
      "read-back path",
      "pool hardening",
    ],
    composition:
      "Pair deterministic pipe allocations with a lifetime or overflow bug, then recover controlled state through a legitimate query path.",
    source: `${kernelSight}arw/pipe-attributes/`,
    related: ["named-pipe-objects", "pool-spray-feng-shui", "use-after-free"],
  }),
  primitive({
    slug: "pool-overflow-to-read-write",
    title: "Pool overflow to read/write",
    summary:
      "Turn an out-of-bounds kernel-pool write into controlled corruption of an adjacent allocation that provides a stronger read or write interface.",
    model:
      "The overflow is only the transport. Reliability comes from allocator bucket selection, neighbor placement, overwrite geometry, target-object invariants, and a safe way to reclaim or read the corrupted object.",
    enables: [
      "Corrupt a neighboring object",
      "Forge length or pointer metadata",
      "Upgrade a crash into a repeatable primitive",
    ],
    constraints: [
      "pool bucket and subsegment",
      "overwrite offset and bytes",
      "neighbor control",
      "allocator hardening",
      "cleanup path",
    ],
    composition:
      "Groom a compatible replacement object, corrupt the smallest useful field, invoke its normal operation to read/write, then avoid destructor crashes.",
    source: `${kernelSight}arw/pool-overflow/`,
    related: ["buffer-overflow", "pool-spray-feng-shui", "pool-hardening"],
  }),
  primitive({
    slug: "pte-manipulation",
    title: "PTE manipulation",
    summary:
      "Read or modify page-table entries to change virtual-to-physical translation or page permissions such as writable, executable, user, or supervisor state.",
    model:
      "A PTE is both an address translation and a policy record. Build-specific layout, paging level, large pages, TLB state, KVA shadowing, and VBS boundaries determine what a bit change actually means.",
    enables: [
      "Make a protected page writable",
      "Change user/supervisor or execute state",
      "Redirect a virtual page to different physical memory",
    ],
    constraints: [
      "PTE address discovery",
      "paging level",
      "large-page state",
      "TLB invalidation",
      "VBS and HVCI ownership",
    ],
    composition:
      "Resolve the correct paging entry, apply a minimal bit transition, synchronize translation state, and choose a target not protected outside VTL0.",
    source: `${kernelSight}arw/pte-manipulation/`,
    related: ["bit-manipulation", "smep-smap", "vbs-hvci"],
  }),
  primitive({
    slug: "registry-based-primitives",
    title: "Registry-based primitives",
    summary:
      "Use privileged registry reads, writes, notifications, callbacks, symbolic links, or configuration consumers to gain persistence, redirection, or a stronger operation.",
    model:
      "A registry write is a capability plus a consumer. The value name, type, 32/64-bit view, security descriptor, caching behavior, and trigger decide whether it matters.",
    enables: [
      "Redirect service or COM configuration",
      "Change driver policy or gate state",
      "Trigger a privileged loader or scheduled action",
    ],
    constraints: [
      "key and value scope",
      "WOW64 view",
      "value type",
      "consumer and trigger",
      "DACL and virtualization",
    ],
    composition:
      "Identify the privileged component that reads the value, the exact time and identity of that read, and the sensitive operation it performs afterward.",
    source: `${kernelSight}arw/registry-based/`,
    related: [
      "registry-callbacks",
      "service-registry-permissions",
      "com-hijacking",
    ],
  }),
  primitive({
    slug: "token-manipulation",
    title: "Token manipulation",
    summary:
      "Change token fields, privileges, groups, integrity, or references so later authorization treats the current execution context as more powerful.",
    model:
      "Choose a minimal semantic target. Token stealing, pointer replacement, privilege-bit edits, SID changes, and integrity changes are separate strategies with different offsets and side effects.",
    enables: [
      "Enable powerful privileges",
      "Adopt SYSTEM identity",
      "Bypass an object access check",
    ],
    constraints: [
      "token address and build layout",
      "field semantics",
      "reference ownership",
      "integrity and session",
      "protected-token checks",
    ],
    composition:
      "Resolve the current token and a viable field, apply a data-only mutation compatible with the build, perform the privileged action, and restore state when possible.",
    source: `${kernelSight}arw/token-manipulation/`,
    related: ["access-tokens", "token-swapping", "bit-manipulation"],
  }),
  primitive({
    slug: "acl-security-descriptor-manipulation",
    title: "ACL and security-descriptor manipulation",
    summary:
      "Change an object's owner, DACL, SACL, mandatory label, or inheritance state to grant a weaker principal rights it should not hold.",
    model:
      "The primitive does not directly execute code. It changes the authorization function so a later open, control, write, or activation succeeds.",
    enables: [
      "Take control of a service, file, key, pipe, device, or process",
      "Grant WRITE_DAC or operation-specific rights",
      "Remove an integrity or inheritance restriction",
    ],
    constraints: [
      "object type",
      "WRITE_DAC or WRITE_OWNER path",
      "ACE ordering",
      "inheritance",
      "mandatory integrity policy",
    ],
    composition:
      "Name the exact newly granted right and the privileged operation it unlocks, then preserve or restore the original descriptor in a lab.",
    source: `${kernelSight}exploitation/acl-sd-manipulation/`,
    related: ["security-descriptors", "weak-service-dacl", "weak-device-dacl"],
  }),
  primitive({
    slug: "io-ring",
    title: "I/O ring exploitation",
    summary:
      "Corrupt or influence I/O ring registration and buffer metadata so legitimate asynchronous I/O machinery performs reads or writes with unintended authority.",
    model:
      "The ring is a privileged consumer of registered state. The useful primitive comes from controlling a buffer array, registration record, or completion path while satisfying version-specific validation.",
    enables: [
      "Kernel-assisted file or memory movement",
      "Read/write composition without direct control-flow hijack",
      "Data-only exploitation on supported builds",
    ],
    constraints: [
      "Windows version",
      "registered-buffer layout",
      "handle and ring state",
      "completion semantics",
      "fixed and changed validation",
    ],
    composition:
      "Establish a valid ring, corrupt only the state consumed by a supported operation, and use completion results to verify bounded access.",
    source: `${kernelSight}exploitation/io-ring/`,
    related: ["arbitrary-read", "arbitrary-write", "io-ring-attack-surface"],
  }),
  primitive({
    slug: "kuser-shared-data",
    title: "KUSER_SHARED_DATA",
    summary:
      "Use the globally mapped shared-data page as a source of time, version, mitigation, and system state—or as a constrained data-only target on affected designs.",
    model:
      "The page has intentionally shared semantics but asymmetric mappings and protections. Every field must be interpreted for the exact build and whether it is kernel-written, user-readable, or shadowed.",
    enables: [
      "Read stable system metadata",
      "Derive timing or version state",
      "Target specific shared fields in historical exploit strategies",
    ],
    constraints: [
      "field offset by build",
      "mapping permissions",
      "update concurrency",
      "KDP or shadowing",
      "consumer semantics",
    ],
    composition:
      "Use version-aware symbols or definitions, identify the privileged consumer of the field, and prove a meaningful state change rather than assuming the page is a universal target.",
    source: `${kernelSight}exploitation/kuser-shared-data/`,
    related: ["information-leak", "kdp", "windows-memory-manager"],
  }),
  primitive({
    slug: "named-pipe-objects",
    title: "Named-pipe kernel objects",
    summary:
      "Use controllable named-pipe server, client, queue, and attribute objects as allocator, identity, synchronization, or read-back building blocks.",
    model:
      "Separate two roles: named pipes as kernel pool objects for memory exploitation, and named pipes as authenticated IPC endpoints for impersonation. Their prerequisites and impacts are different.",
    enables: [
      "Pool grooming and replacement",
      "Deterministic blocking and synchronization",
      "Peer-token impersonation when policy allows",
    ],
    constraints: [
      "server/client role",
      "pipe mode and security",
      "object sizes",
      "queue state",
      "peer identity",
    ],
    composition:
      "Choose either the allocator semantics or the IPC identity semantics, then document the exact object transition and privileged consumer.",
    source: `${kernelSight}exploitation/named-pipe-objects/`,
    related: [
      "pipe-attribute-primitives",
      "named-pipe-impersonation",
      "pool-spray-feng-shui",
    ],
  }),
  primitive({
    slug: "palette-bitmap-objects",
    title: "Palette and bitmap object primitives",
    summary:
      "Historical win32k techniques corrupt GDI object metadata so Set/Get operations read or write through redirected kernel pointers.",
    model:
      "One object is often the manager that redirects an address field; another is the worker whose legitimate API performs the transfer. Modern builds changed isolation and object layouts, so treat this as a historical pattern rather than a universal recipe.",
    enables: [
      "Historical win32k arbitrary read/write",
      "Manager/worker object pattern",
      "Study of object-corruption composition",
    ],
    constraints: [
      "Windows build",
      "GDI object isolation",
      "kernel pointer availability",
      "manager/worker placement",
      "mitigation changes",
    ],
    composition:
      "Use the pattern to understand object-oriented exploitation, then validate whether the target build still exposes the same fields and user/kernel mappings.",
    source: `${kernelSight}exploitation/palette-bitmap/`,
    related: ["win32k-subsystem", "pool-spray-feng-shui", "arbitrary-write"],
  }),
  primitive({
    slug: "pool-spray-feng-shui",
    title: "Pool spray and heap feng shui",
    summary:
      "Shape allocator state so a vulnerable allocation gains a predictable neighbor, replacement object, size class, or reuse sequence.",
    model:
      "Grooming changes probability; it is not a primitive by itself. Record allocation API, pool type, tag, size bucket, CPU locality, holes, replacement lifetime, and destructor behavior.",
    enables: [
      "Place controlled neighbors",
      "Reclaim a freed slot",
      "Turn a relative overwrite into a semantic object corruption",
    ],
    constraints: [
      "allocator bucket",
      "CPU and NUMA locality",
      "pool type and tag",
      "allocation lifetime",
      "hardening and randomness",
    ],
    composition:
      "Create and free allocations in a measured sequence, trigger the bug at a stable point, and use a target object's normal operation for confirmation.",
    source: `${kernelSight}exploitation/pool-spray-feng-shui/`,
    related: [
      "windows-kernel-pool",
      "use-after-free",
      "pool-overflow-to-read-write",
    ],
  }),
  primitive({
    slug: "previous-mode-manipulation",
    title: "PreviousMode manipulation",
    summary:
      "Alter the current thread's previous-mode state so later native operations treat user-controlled arguments as trusted kernel input.",
    model:
      "This is a thread-local data-only strategy. Its value comes from the next syscall or kernel routine whose probing or access checks differ for KernelMode, and from safely restoring the original mode.",
    enables: [
      "Suppress selected user-pointer probes",
      "Change object-manager access behavior",
      "Compose a constrained write into stronger native operations",
    ],
    constraints: [
      "current thread only",
      "build-specific field location",
      "write size",
      "next-call semantics",
      "safe restoration",
    ],
    composition:
      "Pin execution to the modified thread, choose a native call with a precisely understood mode-dependent path, and restore state before unrelated kernel work occurs.",
    source: `${kernelSight}exploitation/previous-mode-manipulation/`,
    related: ["requestor-mode", "constrained-write", "arbitrary-write"],
  }),
  primitive({
    slug: "token-swapping",
    title: "Token swapping",
    summary:
      "Replace or redirect the token reference used by a process or thread so it executes under another security context.",
    model:
      "A token pointer contains reference and fast-reference bits on many builds. A reliable swap preserves encoding, lifetime, session, and process invariants rather than copying a raw address blindly.",
    enables: [
      "Adopt a SYSTEM primary token",
      "Change the effective authorization context",
      "Demonstrate data-only LPE",
    ],
    constraints: [
      "token pointer encoding",
      "reference counts",
      "process and token addresses",
      "session and integrity",
      "cleanup",
    ],
    composition:
      "Resolve both process objects, preserve low-bit metadata, maintain references where required, perform the privileged action, and avoid leaving an unstable process object.",
    source: `${kernelSight}exploitation/token-swapping/`,
    related: ["token-manipulation", "access-tokens", "arbitrary-write"],
  }),
  primitive({
    slug: "wnf-state-data",
    title: "WNF state-data primitives",
    summary:
      "Use Windows Notification Facility state names and state-data objects as controllable allocations, lifetime targets, or information channels.",
    model:
      "WNF exposes a stateful publish/subscribe abstraction backed by kernel-managed objects. Exploitation depends on scope, ownership, size, lifetime, subscription state, and build-specific internals.",
    enables: [
      "Controlled kernel allocations",
      "Lifetime and replacement patterns",
      "Stateful read-back or notification behavior",
    ],
    constraints: [
      "scope and lifetime",
      "state-data size",
      "access policy",
      "subscription concurrency",
      "build layout",
    ],
    composition:
      "Use documented state operations to shape or observe objects, then pair them with a separate corruption bug rather than treating WNF itself as the vulnerability.",
    source: `${kernelSight}exploitation/wnf-state-data/`,
    related: ["wnf-attack-surface", "pool-spray-feng-shui", "race-conditions"],
  }),
  primitive({
    slug: "arbitrary-file-read",
    title: "Arbitrary file read",
    summary:
      "Make a privileged component disclose bytes from an attacker-selected file or path that the caller could not read directly.",
    model:
      "Separate path selection from content return. DACL bypass, sharing-mode bypass, backup semantics, device-path access, and a privileged proxy all create different boundaries.",
    enables: [
      "Read secrets or configuration",
      "Recover credentials or keys",
      "Resolve state for a later write or impersonation chain",
    ],
    constraints: [
      "path syntax",
      "DACL and share mode",
      "file type",
      "offset and length",
      "where returned bytes go",
    ],
    composition:
      "Prove the privileged principal opens the chosen object and that the content is returned across the boundary without an equivalent direct read path.",
    related: [
      "path-canonicalization",
      "privileged-file-operations",
      "information-leak",
    ],
  }),
  primitive({
    slug: "arbitrary-file-create",
    title: "Arbitrary file creation",
    summary:
      "Create a new file at an attacker-selected privileged path, with impact determined by content, owner, DACL, disposition, and the consumer of that path.",
    model:
      "Creation is not automatically overwrite. Ask whether parents already exist, whether collisions fail, who owns the new file, which DACL is inherited, and who later loads or parses it.",
    enables: [
      "Plant configuration or loader input",
      "Create a future replacement target",
      "Occupy a privileged namespace name",
    ],
    constraints: [
      "parent control",
      "create disposition",
      "content control",
      "owner and inherited DACL",
      "privileged consumer",
    ],
    composition:
      "Select a path that a stronger principal later trusts, and prove creation semantics allow the intended bytes and security descriptor to survive until the trigger.",
    related: [
      "arbitrary-directory-create",
      "dll-hijacking",
      "privileged-file-operations",
    ],
  }),
  primitive({
    slug: "arbitrary-file-write",
    title: "Arbitrary file write or overwrite",
    summary:
      "Write controlled bytes to a privileged file, with append-only, offset-limited, truncating, replacement, and whole-file variants modeled separately.",
    model:
      "A file write becomes execution only through a consumer. Track open disposition, share mode, file identity, owner/DACL, atomic replacement behavior, and the exact privileged trigger.",
    enables: [
      "Modify configuration or executable input",
      "Plant a DLL or script for a privileged loader",
      "Corrupt trusted state",
    ],
    constraints: [
      "content and offset",
      "append or truncate behavior",
      "existing-file requirement",
      "ownership and DACL",
      "consumer and trigger",
    ],
    composition:
      "Find a reliable privileged consumer whose path, format, signature policy, and timing match the write primitive; do not stop at the ability to change bytes.",
    related: [
      "dll-hijacking",
      "service-binary-path",
      "privileged-file-operations",
    ],
  }),
  primitive({
    slug: "arbitrary-file-delete",
    title: "Arbitrary file delete",
    summary:
      "Cause a privileged principal to delete an attacker-selected file that the caller cannot remove directly.",
    model:
      "Delete is usually a denial-of-service primitive until a protected file's absence triggers fail-open behavior, rollback, repair, recreation with weaker ownership, or a delete-to-create conversion.",
    enables: [
      "Remove protected state",
      "Trigger repair or rollback",
      "Prepare replacement when name ownership changes after deletion",
    ],
    constraints: [
      "file versus link identity",
      "delete-pending semantics",
      "open handles",
      "recreation owner and DACL",
      "recovery consumer",
    ],
    composition:
      "Prove the chosen object is deleted, then document the separate mechanism that converts absence into controlled privileged state or execution.",
    related: [
      "installer-rollback",
      "reparse-points",
      "privileged-file-operations",
    ],
  }),
  primitive({
    slug: "arbitrary-file-move",
    title: "Arbitrary file move or rename",
    summary:
      "Move or rename a controlled or privileged file across attacker-selected names, directories, or replacement targets.",
    model:
      "A rename is a namespace operation on an existing file object. Replace-if-exists, POSIX semantics, volume boundaries, open handles, resulting parent DACL, and final ownership determine its strength.",
    enables: [
      "Replace a trusted path atomically",
      "Move controlled content into a privileged directory",
      "Displace protected configuration",
    ],
    constraints: [
      "same-volume requirement",
      "replace semantics",
      "source control",
      "destination parent",
      "resulting ownership and DACL",
    ],
    composition:
      "Bind the operation to source and destination handles where possible, then identify the privileged consumer that trusts the final name.",
    related: [
      "arbitrary-file-write",
      "reparse-points",
      "path-canonicalization",
    ],
  }),
  primitive({
    slug: "arbitrary-directory-create",
    title: "Arbitrary directory creation",
    summary:
      "Create an NTFS or Object Manager directory at an attacker-selected privileged path or namespace location.",
    model:
      "Filesystem directories and Object Manager directories are different object types. Impact comes from the child names the attacker can subsequently create and the privileged resolver that enters the directory.",
    enables: [
      "Namespace shadowing",
      "Placement of symbolic links or controlled children",
      "Preparation for privileged extraction or creation",
    ],
    constraints: [
      "namespace type",
      "parent DACL",
      "owner and inheritance",
      "collision behavior",
      "future resolver",
    ],
    composition:
      "Show who can populate the new directory and which stronger principal later resolves a child name through it.",
    related: [
      "object-manager-namespaces",
      "object-manager-symbolic-links",
      "arbitrary-file-create",
    ],
  }),
  primitive({
    slug: "arbitrary-directory-delete",
    title: "Arbitrary directory deletion",
    summary:
      "Remove or empty an attacker-selected directory through privileged cleanup, recursion, or namespace redirection.",
    model:
      "Record whether traversal follows reparse points, crosses volumes, removes non-empty trees, respects open handles, and recreates parents with different security.",
    enables: [
      "Remove protected application state",
      "Trigger repair or fallback paths",
      "Prepare namespace replacement",
    ],
    constraints: [
      "recursive traversal",
      "reparse behavior",
      "non-empty handling",
      "open descendants",
      "recreation semantics",
    ],
    composition:
      "Demonstrate a conversion through recovery, fallback, or controlled recreation; deletion alone is not equivalent to privilege escalation.",
    related: ["arbitrary-file-delete", "reparse-points", "installer-rollback"],
  }),
  primitive({
    slug: "junction-mount-point",
    title: "Junction and mount-point redirection",
    summary:
      "Use an NTFS reparse point on a directory so a later filesystem lookup continues at a different target path or volume.",
    model:
      "A junction redirects filesystem traversal. It is interpreted after the Object Manager has selected the volume device, and each later path component can introduce another identity or authorization decision.",
    enables: [
      "Redirect privileged file operations",
      "Escape an attacker-owned staging directory",
      "Construct deterministic path races",
    ],
    constraints: [
      "who controls the junction",
      "when resolution occurs",
      "open-handle binding",
      "reparse tag policy",
      "target path namespace",
    ],
    composition:
      "Place the reparse point in a directory the privileged component traverses, synchronize the lookup, and prove it acts on the redirected final object.",
    related: [
      "reparse-points",
      "oplock-assisted-race",
      "object-manager-symbolic-links",
    ],
  }),
  primitive({
    slug: "object-manager-symbolic-links",
    title: "Object Manager symbolic links",
    summary:
      "Create or influence an NT namespace symbolic link so object lookup resolves a trusted name to a different kernel object or filesystem path.",
    model:
      "This is not an NTFS symlink. The Object Manager resolves it inside an object directory such as a DOS-device map or RPC Control before a filesystem may become involved.",
    enables: [
      "Redirect NT object opens",
      "Bridge an Object Manager name into a filesystem path",
      "Exploit namespace recreation and shadowing",
    ],
    constraints: [
      "object directory DACL",
      "session namespace",
      "link lifetime",
      "resolver path",
      "collision and permanence",
    ],
    composition:
      "Control the directory or link name, induce privileged re-resolution, and show the final object differs from the one validated earlier.",
    related: [
      "object-manager-namespaces",
      "arbitrary-directory-create",
      "junction-mount-point",
    ],
  }),
  primitive({
    slug: "hard-link-creation",
    title: "Hard-link creation",
    summary:
      "Give an existing file another name and induce a privileged writer to modify the same file through a path it trusts.",
    model:
      "Hard links bind names to one file record on the same volume. Link creation restrictions, file ownership, parent permissions, open handles, and the writer's replacement semantics decide viability.",
    enables: [
      "Redirect a privileged write to an existing file",
      "Reuse a trusted writer as a confused deputy",
      "Preserve file identity across names",
    ],
    constraints: [
      "same-volume identity",
      "ownership restrictions",
      "destination parent",
      "writer disposition",
      "modern hard-link mitigations",
    ],
    composition:
      "Prove the privileged component opens the linked file for in-place modification rather than safely replacing it with a new file object.",
    related: [
      "arbitrary-file-write",
      "path-canonicalization",
      "privileged-file-operations",
    ],
  }),
  primitive({
    slug: "reparse-point-substitution",
    title: "Reparse-point substitution",
    summary:
      "Swap or retarget a reparse point between validation and use so privileged code acts on a different object than the one it checked.",
    model:
      "This is a path-identity race. The important event is not creating a reparse point but invalidating a prior name-based decision before a second resolution.",
    enables: [
      "TOCTOU path redirection",
      "Privileged file create, delete, move, or write conversion",
      "Escape from a validated directory tree",
    ],
    constraints: [
      "race window",
      "directory ownership",
      "reparse policy",
      "handle versus name use",
      "final-object validation",
    ],
    composition:
      "Use an oplock or namespace loop to synchronize the swap, then verify final identity through the handle actually used for the sensitive operation.",
    related: [
      "toctou-double-fetch",
      "oplock-assisted-race",
      "junction-mount-point",
    ],
  }),
  primitive({
    slug: "oplock-assisted-race",
    title: "Oplock-assisted path race",
    summary:
      "Use an opportunistic lock to pause a filesystem operation at a predictable point while the attacker mutates names, directories, links, or object identity.",
    model:
      "The oplock is synchronization, not the vulnerability. It makes a time-of-check/time-of-use window deterministic enough to replace the object or namespace state between two privileged actions.",
    enables: [
      "Deterministic namespace mutation",
      "Reliable TOCTOU reproduction",
      "Observation of the privileged operation order",
    ],
    constraints: [
      "oplock eligibility",
      "break timing",
      "which handle is blocked",
      "mutation rights",
      "retry behavior",
    ],
    composition:
      "Block the operation, confirm the privileged thread is inside the desired window, replace the namespace state, and release the oplock to complete the second lookup.",
    related: [
      "race-conditions",
      "reparse-point-substitution",
      "path-canonicalization",
    ],
  }),
  primitive({
    slug: "privileged-file-copy-restore",
    title: "Privileged file copy, extraction, and restore",
    summary:
      "Influence bytes or paths consumed by a privileged copier, updater, quarantine engine, archive extractor, repair task, or restore service.",
    model:
      "These components are confused-deputy candidates because they combine broad file rights with attacker-influenced source, destination, archive metadata, or recovery state.",
    enables: [
      "Create or overwrite privileged files",
      "Cross a DACL or sharing boundary",
      "Convert controlled staging content into a trusted location",
    ],
    constraints: [
      "source trust",
      "destination validation",
      "archive traversal",
      "link handling",
      "owner and inherited DACL",
    ],
    composition:
      "Trace source selection through canonicalization to the final destination handle, then identify the privileged consumer of the restored content.",
    related: [
      "arbitrary-file-create",
      "arbitrary-file-write",
      "installer-updater-surface",
    ],
  }),
];
