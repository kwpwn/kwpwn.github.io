import type { HandbookConcept } from "./windows-security-handbook";
import { makeConcept } from "./windows-security-catalog-helpers";

const base = "https://splintersfury.github.io/KernelSight/driver-types";

export const driverTypeConcepts: HandbookConcept[] = [
  makeConcept({
    slug: "core-kernel",
    title: "Core kernel components",
    group: "driver-types",
    level: "Advanced",
    summary:
      "Executive, object, memory, process, I/O, security, configuration, and scheduling components implement system-wide invariants and are reached through syscalls and internal dispatch.",
    model:
      "Map the owning executive subsystem, public/native entry point, object types, locks, privilege boundary, and build-specific implementation before assuming a third-party-driver technique transfers directly.",
    enables: [
      "Study system-wide kernel invariants",
      "Connect Native APIs to internal objects",
      "Prioritize high-impact cross-subsystem state",
    ],
    checks: [
      "Which executive manager owns the object?",
      "What syscall or internal callback reaches it?",
      "Which locks and reference rules apply?",
      "Is the state protected by VBS, KDP, or other out-of-band policy?",
    ],
    source: `${base}/core-kernel/`,
    related: [
      "windows-memory-manager",
      "object-manager-namespaces",
      "access-tokens",
    ],
  }),
  makeConcept({
    slug: "filesystem-drivers",
    title: "File system drivers",
    group: "driver-types",
    summary:
      "Filesystem drivers translate file and volume operations into metadata, caching, security, namespace, recovery, and storage behavior.",
    model:
      "Follow file objects, volume control blocks, file control blocks, contexts, cache manager interactions, oplocks, reparses, and on-disk metadata as one lifecycle.",
    enables: [
      "Analyze parser and metadata bugs",
      "Map namespace and security behavior",
      "Study cache, transaction, and recovery state",
    ],
    checks: [
      "Which media or caller controls metadata?",
      "How are file identities and names normalized?",
      "Can cleanup, close, dismount, or recovery race active I/O?",
      "Which paths run before access checks or mount trust?",
    ],
    source: `${base}/filesystem/`,
    related: ["filesystem-irps", "ntfs", "storage-caching-drivers"],
  }),
  makeConcept({
    slug: "minifilter-drivers",
    title: "File system minifilters",
    group: "driver-types",
    summary:
      "Minifilters register pre/post callbacks around file operations to inspect, block, redirect, scan, quarantine, encrypt, or virtualize I/O.",
    model:
      "Build a callback matrix by major function and altitude. Track operation status, reparse decisions, callback data lifetime, name-query safety, contexts, deferred work, and whether the filter impersonates.",
    enables: [
      "Audit EDR and security filters",
      "Find privileged file-operation deputies",
      "Study callback state and teardown races",
    ],
    checks: [
      "Which operations and altitudes are registered?",
      "Can a name be queried safely in this callback?",
      "Does post-operation state trust a path checked earlier?",
      "Are stream, instance, and transaction contexts referenced correctly?",
    ],
    source: `${base}/minifilter/`,
    related: [
      "filesystem-irps",
      "third-party-security-drivers",
      "privileged-file-operations",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "log-transaction-drivers",
    title: "Log and transaction drivers",
    group: "driver-types",
    summary:
      "Logging, journaling, transaction, and recovery components maintain complex persistent metadata and replay state across crashes, reopens, and partial operations.",
    model:
      "Treat durable state as an untrusted protocol with epochs, sequence numbers, offsets, checksums, container relationships, commit/rollback, and recovery transitions.",
    enables: [
      "Research CLFS and transaction surfaces",
      "Find parser and recovery differentials",
      "Study persistent corruption across restarts",
    ],
    checks: [
      "Can the attacker create or modify log state?",
      "Are normal and recovery validators equivalent?",
      "Do integer ranges survive serialization?",
      "Can partial state be replayed twice or out of order?",
    ],
    source: `${base}/log-transaction/`,
    related: ["clfs", "unsafe-protocol-parsing", "patch-diffing"],
  }),
  makeConcept({
    slug: "kernel-streaming-drivers",
    title: "Kernel Streaming drivers",
    group: "driver-types",
    summary:
      "Kernel Streaming models multimedia filters, pins, nodes, properties, events, topology, and data flows accessed through structured IOCTL/property protocols.",
    model:
      "Enumerate filter factories, pins, property sets, method/event sets, instance data, topology IDs, and buffer transfer models. Many inputs are nested variable-length structures.",
    enables: [
      "Map rich device property protocols",
      "Find type, length, and topology confusion",
      "Research broadly deployed media drivers",
    ],
    checks: [
      "Which property and method sets are exposed?",
      "Are instance and value lengths cross-validated?",
      "Can pin state race teardown or format changes?",
      "Do third-party handlers trust framework-parsed identifiers?",
    ],
    source: `${base}/kernel-streaming/`,
    related: ["unsafe-protocol-parsing", "ioctl-handlers", "race-conditions"],
  }),
  makeConcept({
    slug: "network-stack-drivers",
    title: "Network stack drivers",
    group: "driver-types",
    summary:
      "Miniports, protocol drivers, lightweight filters, WFP callouts, virtual switches, transport helpers, and endpoint drivers process local and remote traffic under high concurrency.",
    model:
      "Classify remote versus local reachability, packet ownership, parsing layer, offload state, callback IRQL, policy identity, and detach/pause lifecycle.",
    enables: [
      "Prioritize remote attack surfaces",
      "Audit packet-parser and policy code",
      "Find buffer-ownership and teardown races",
    ],
    checks: [
      "Can unauthenticated remote input reach the path?",
      "Who owns and frees packet buffers?",
      "Are fragmented/offloaded lengths consistent?",
      "Can interface changes race callbacks?",
    ],
    source: `${base}/network-stack/`,
    related: ["ndis-network", "afd", "unsafe-protocol-parsing"],
  }),
  makeConcept({
    slug: "storage-caching-drivers",
    title: "Storage and caching drivers",
    group: "driver-types",
    summary:
      "Disk, volume, class, port, cache, encryption, snapshot, and virtual-storage drivers translate block operations while managing DMA, queues, metadata, and device state.",
    model:
      "Follow an I/O from filesystem to volume to class/port/miniport, including request splitting, MDLs, scatter-gather lists, cache state, cancellation, reset, and hot removal.",
    enables: [
      "Audit block and control IOCTLs",
      "Study DMA and buffer lifetime",
      "Research snapshot, encryption, and virtual-disk parsers",
    ],
    checks: [
      "Which IOCTLs reach hardware or metadata parsers?",
      "Are sector, block, byte, and alignment units consistent?",
      "Can reset or removal race queued requests?",
      "Are user mappings constrained to owned ranges?",
    ],
    source: `${base}/storage-caching/`,
    related: ["dma-mmio-access", "mdl-mapping", "pnp-and-power"],
  }),
  makeConcept({
    slug: "security-policy-drivers",
    title: "Security and policy drivers",
    group: "driver-types",
    summary:
      "Antimalware, anti-cheat, DLP, VPN, encryption, monitoring, and policy drivers register broad callbacks and often expose privileged control channels to companion services.",
    model:
      "Map protected assets, callbacks, filters, telemetry, device DACL, gate/handshake, service relationship, update path, self-protection, and fail-open/fail-closed behavior.",
    enables: [
      "Audit privileged security boundaries",
      "Find callback and IPC weaknesses",
      "Understand EDR or anti-cheat driver behavior",
    ],
    checks: [
      "Which principals can open the control device?",
      "What does the vendor gate actually prove?",
      "Can policy registry or update state be modified?",
      "Do callbacks trust stale process, path, or token identity?",
    ],
    source: `${base}/security-policy/`,
    related: [
      "third-party-security-drivers",
      "driver-gates-and-handshakes",
      "registry-callbacks",
    ],
  }),
  makeConcept({
    slug: "third-party-security-drivers",
    title: "Third-party security drivers",
    group: "driver-types",
    summary:
      "Vendor security products combine kernel callbacks, filters, scanners, process protection, telemetry, and privileged services with complex update and compatibility requirements.",
    model:
      "Treat the product as a distributed privileged system: driver, service, UI, updater, policy store, IPC, cloud control, and self-protection each introduce a boundary.",
    enables: [
      "End-to-end EDR driver analysis",
      "Find user/kernel trust mismatches",
      "Separate protection goals from exposed attack surface",
    ],
    checks: [
      "Which component owns authorization?",
      "Can ordinary users influence policy, quarantine, or update paths?",
      "Are handles and sessions bound to the right client?",
      "What happens when one component is missing or outdated?",
    ],
    source: `${base}/third-party-security/`,
    related: [
      "security-policy-drivers",
      "minifilter-drivers",
      "driver-gates-and-handshakes",
    ],
  }),
  makeConcept({
    slug: "vendor-utility-drivers",
    title: "Vendor utility drivers",
    group: "driver-types",
    summary:
      "Hardware-monitoring, RGB, tuning, firmware, overclocking, diagnostic, and OEM utilities often expose MSR, port, PCI, MMIO, physical-memory, or firmware functionality to a companion application.",
    model:
      "Inventory backend operations first, then work backward through address allowlists, IOCTL rights, device DACL, caller gates, service mediation, and installation scope.",
    enables: [
      "Find BYOVD-capable interfaces",
      "Audit hardware and firmware access",
      "Study weak vendor-client recognition",
    ],
    checks: [
      "Can a standard user or admin open the device?",
      "Can the caller select arbitrary physical or kernel targets?",
      "Is the gate reproducible from shipped software?",
      "Do range checks cover overflow and device ownership?",
    ],
    source: `${base}/vendor-utility/`,
    related: [
      "direct-ioctl-read-write",
      "driver-gates-and-handshakes",
      "byovd",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "performance-and-gpu-drivers",
    title: "Performance and GPU drivers",
    group: "driver-types",
    summary:
      "Graphics and accelerator stacks expose command submission, shared allocations, user mappings, synchronization, scheduling, telemetry, firmware, MMIO, and complex memory-management paths.",
    model:
      "Map process/device contexts, command buffers, residency, virtual address spaces, shared resources, fence lifetime, kernel/user mappings, resets, and firmware validation.",
    enables: [
      "Research high-complexity parsers and memory managers",
      "Study shared GPU/CPU memory",
      "Audit escape IOCTLs and firmware channels",
    ],
    checks: [
      "Which command data is user-controlled?",
      "Are GPU virtual addresses bound to the right process context?",
      "Can reset race completion or resource teardown?",
      "Are MMIO and physical mappings range-limited?",
    ],
    source: `${base}/performance-gpu/`,
    related: ["dma-mmio-access", "shared-memory", "race-conditions"],
  }),
  makeConcept({
    slug: "win32k-subsystem",
    title: "Win32k subsystem",
    group: "driver-types",
    summary:
      "The kernel GUI subsystem manages windows, graphics, input, desktops, sessions, fonts, composition, and user objects with a large syscall and callback surface.",
    model:
      "Study session/desktop isolation, user handles, kernel objects, callback reentrancy, object locks, user-mode mirrors, and the effects of win32k lockdown and component separation.",
    enables: [
      "Analyze GUI kernel vulnerabilities",
      "Understand historical GDI primitives",
      "Study callbacks and cross-process user objects",
    ],
    checks: [
      "Which session and desktop own the object?",
      "Can user callbacks reenter the operation?",
      "Are shadow structures mutable after validation?",
      "Which build removed or isolated the target field?",
    ],
    source: `${base}/win32k/`,
    related: [
      "win32k-attack-surface",
      "palette-bitmap-objects",
      "race-conditions",
    ],
  }),
  makeConcept({
    slug: "wdm-wdf-driver-models",
    title: "WDM, KMDF, and UMDF driver models",
    group: "driver-types",
    level: "Foundation",
    summary:
      "WDM exposes IRPs and lifecycle mechanics directly; KMDF and UMDF wrap them in framework objects, queues, callbacks, and policy with different execution and trust contexts.",
    model:
      "Identify the driver model before auditing. The same user operation appears as a raw dispatch routine, a KMDF queue callback, or a user-mode framework callback with different ownership and security defaults.",
    enables: [
      "Navigate driver architecture quickly",
      "Select correct debugging and fuzzing hooks",
      "Apply framework-specific lifetime rules",
    ],
    checks: [
      "Which framework and version apply?",
      "Where is device security configured?",
      "Which object owns each context?",
      "What execution level and synchronization scope apply?",
    ],
    sources: [
      {
        title: "Choose a driver model",
        href: "https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/choosing-a-driver-model",
        kind: "primary",
      },
    ],
    related: ["wdf-kmdf", "irp-and-io-stack", "pnp-and-power"],
  }),
];
