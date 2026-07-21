import type { HandbookConcept } from "./windows-security-handbook";
import { makeConcept } from "./windows-security-catalog-helpers";

const base = "https://splintersfury.github.io/KernelSight/attack-surfaces";

export const attackSurfaceConcepts: HandbookConcept[] = [
  makeConcept({
    slug: "ioctl-handlers",
    title: "IOCTL handlers",
    group: "attack-surfaces",
    summary:
      "User or kernel callers submit control codes and buffers through device handles to dispatch routines that often expose a driver's most privileged custom operations.",
    model:
      "Build a table of device name, DACL, create policy, IOCTL value, access bits, method, input/output shape, gate state, and final backend operation.",
    enables: [
      "Reach vendor-defined driver functionality",
      "Map memory and hardware operations",
      "Systematically fuzz request parsers and state",
    ],
    checks: [
      "Who can open the device?",
      "Which IOCTLs use FILE_ANY_ACCESS?",
      "How are every offset, count, and buffer length validated?",
      "Are sensitive subcommands protected after a broad dispatcher gate?",
    ],
    source: `${base}/ioctl-handlers/`,
    related: [
      "ioctl-encoding-and-buffering",
      "driver-gates-and-handshakes",
      "direct-ioctl-read-write",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "irp-create-and-close",
    title: "IRP_MJ_CREATE, cleanup, and close",
    group: "attack-surfaces",
    summary:
      "Handle creation and teardown establish per-file authorization, parse open-time protocol data, bind process state, and release resources used by later requests.",
    model:
      "Treat create-to-cleanup-to-close as a session lifecycle. State should belong to the file object, transitions must be synchronized, and cleanup must revoke capabilities before resources disappear.",
    enables: [
      "Audit open-time gates",
      "Find cross-handle state leaks",
      "Find lifetime and cancellation bugs",
    ],
    checks: [
      "What data is accepted during create?",
      "Is authorization global or per-file?",
      "Can a duplicated handle retain or transfer state?",
      "Do cleanup and close race in-flight requests?",
    ],
    related: ["driver-gates-and-handshakes", "logic-bugs", "use-after-free"],
  }),
  makeConcept({
    slug: "filesystem-irps",
    title: "Filesystem IRPs",
    group: "attack-surfaces",
    summary:
      "Create, read, write, query/set information, directory control, cleanup, and filesystem-control IRPs traverse filesystem and filter stacks with path, handle, buffer, and security state.",
    model:
      "Follow both the file object and the name. Parse callbacks, reparses, normalization, oplocks, caching, alternate streams, transactions, and completion can change the meaning of the request.",
    enables: [
      "Filesystem parser research",
      "Path-identity and reparse analysis",
      "Minifilter callback and context review",
    ],
    checks: [
      "Which major/minor function is reachable?",
      "Is the path reparsed or normalized more than once?",
      "Does the driver trust a file name after opening?",
      "Are stream, volume, and transaction contexts lifetime-safe?",
    ],
    source: `${base}/filesystem-irps/`,
    related: [
      "filesystem-drivers",
      "minifilter-drivers",
      "filesystem-namespace-surface",
    ],
  }),
  makeConcept({
    slug: "alpc",
    title: "ALPC",
    group: "attack-surfaces",
    summary:
      "Advanced Local Procedure Call provides kernel-mediated local messaging, ports, connection state, handles, sections, views, and security context used by many Windows services and subsystems.",
    model:
      "Map port creation, connection, message attributes, handle/view transfer, peer token, impersonation, and teardown as one stateful protocol.",
    enables: [
      "Reach privileged local services",
      "Transfer handles and shared views",
      "Study peer-identity and lifetime bugs",
    ],
    checks: [
      "Who can connect to the port?",
      "How is peer identity captured and revalidated?",
      "Which message attributes carry handles or views?",
      "Can disconnect race reply, cancellation, or object cleanup?",
    ],
    source: `${base}/alpc/`,
    related: ["rpc-services", "shared-memory", "authorization-bypass"],
  }),
  makeConcept({
    slug: "shared-memory",
    title: "Shared memory and sections",
    group: "attack-surfaces",
    summary:
      "Processes and drivers exchange data through section objects, mapped views, registered buffers, and shared control structures whose contents can change concurrently.",
    model:
      "A shared buffer is attacker-controlled for its entire lifetime unless copied into private storage. Validate offsets and state atomically, define ownership, and version the protocol.",
    enables: [
      "High-throughput IPC research",
      "Double-fetch and race discovery",
      "Cross-process mapping and permission analysis",
    ],
    checks: [
      "Who creates and maps the section?",
      "Can the client mutate data after validation?",
      "Are offsets relative to the mapped view and overflow-safe?",
      "How are disconnect and unmap synchronized?",
    ],
    source: `${base}/shared-memory/`,
    related: ["toctou-double-fetch", "alpc", "mdl-mapping"],
  }),
  makeConcept({
    slug: "registry-callbacks",
    title: "Registry callbacks",
    group: "attack-surfaces",
    summary:
      "Kernel callbacks observe or filter registry operations and receive names, objects, transaction state, buffers, and pre/post-operation context at sensitive lifecycle points.",
    model:
      "Build a callback matrix by notification class. Pre and post structures differ, object names can be relative or stale, and blocking or rewriting requests changes ownership and completion rules.",
    enables: [
      "Audit security-product policy",
      "Find callback lifetime and context bugs",
      "Analyze privileged registry mediation",
    ],
    checks: [
      "Which REG_NOTIFY_CLASS values are handled?",
      "Are pre/post structures interpreted correctly?",
      "Can names be queried safely at this point?",
      "Are callback and transaction contexts released on every path?",
    ],
    source: `${base}/registry-callbacks/`,
    related: [
      "security-policy-drivers",
      "registry-based-primitives",
      "race-conditions",
    ],
  }),
  makeConcept({
    slug: "ndis-network",
    title: "NDIS and the network stack",
    group: "attack-surfaces",
    summary:
      "NDIS miniports, protocol drivers, lightweight filters, WFP callouts, and network parsers handle remote or local packet data under high concurrency and complex ownership rules.",
    model:
      "Track packet origin, NET_BUFFER_LIST ownership, clone/reference state, offload metadata, IRQL, cancellation, and whether parsing happens before authentication or policy.",
    enables: [
      "Remote and local packet-parser research",
      "Filter/callout policy review",
      "Lifetime and concurrency analysis",
    ],
    checks: [
      "Is the input remotely reachable?",
      "Who owns each NET_BUFFER_LIST?",
      "Are fragmented and offloaded lengths consistent?",
      "Can pause, detach, or cancellation race callbacks?",
    ],
    source: `${base}/ndis-network/`,
    related: [
      "network-stack-drivers",
      "race-conditions",
      "unsafe-protocol-parsing",
    ],
  }),
  makeConcept({
    slug: "pnp-and-power",
    title: "Plug and Play and power",
    group: "attack-surfaces",
    summary:
      "PnP and power transitions create, start, stop, remove, surprise-remove, and suspend device stacks while I/O, callbacks, and user handles may still exist.",
    model:
      "Use a state machine: device present, started, stopping, removed, and powered states. Every request and callback must be legal for the current state and protected by references or rundown.",
    enables: [
      "Find teardown races",
      "Audit stale device state",
      "Exercise hardware and virtual-device lifecycle paths",
    ],
    checks: [
      "Can I/O arrive during stop or remove?",
      "Which lock or rundown protects device context?",
      "Are queues purged before resources are unmapped?",
      "Do surprise removal and failed-start paths release the same state twice?",
    ],
    source: `${base}/pnp-power/`,
    related: ["use-after-free", "wdf-kmdf", "driver-lifecycle"],
  }),
  makeConcept({
    slug: "wdf-kmdf",
    title: "WDF and KMDF surfaces",
    group: "attack-surfaces",
    summary:
      "Windows Driver Frameworks manage objects, queues, request buffers, callbacks, PnP state, and cleanup, reducing boilerplate while introducing framework-specific ownership and configuration rules.",
    model:
      "Audit configured object parents, execution level, synchronization scope, queue dispatch mode, file-object context, request buffer retrieval, and cleanup callbacks.",
    enables: [
      "Map framework dispatch quickly",
      "Find context and parent-lifetime mistakes",
      "Verify queue and buffer contracts",
    ],
    checks: [
      "Which queue receives each request?",
      "Are callbacks sequential or parallel?",
      "Which WDF object owns each context?",
      "Are minimum buffer lengths checked by the retrieval API and then rechecked semantically?",
    ],
    source: `${base}/wdf/`,
    related: ["ioctl-handlers", "pnp-and-power", "driver-gates-and-handshakes"],
  }),
  makeConcept({
    slug: "wmi-etw",
    title: "WMI and ETW",
    group: "attack-surfaces",
    summary:
      "Management and tracing providers accept queries, methods, registration state, enable callbacks, and event data across user/kernel boundaries and privileged diagnostic workflows.",
    model:
      "Separate control plane from telemetry. Provider registration and enable state affect who can trigger callbacks; event buffers and schemas affect what data crosses the boundary.",
    enables: [
      "Reach management-provider methods",
      "Audit trace callbacks and buffer construction",
      "Correlate runtime behavior without patching code",
    ],
    checks: [
      "Who can enable or invoke the provider?",
      "Are WMI method buffers length-checked?",
      "Can enable/disable race teardown?",
      "Does telemetry disclose pointers, secrets, or cross-user data?",
    ],
    source: `${base}/wmi-etw/`,
    related: [
      "security-policy-drivers",
      "uninitialized-memory",
      "runtime-tracing",
    ],
  }),
  makeConcept({
    slug: "clfs",
    title: "Common Log File System (CLFS)",
    group: "attack-surfaces",
    summary:
      "CLFS parses and manages base log files, metadata blocks, containers, records, marshaling areas, and recovery state in a complex kernel subsystem reachable through filesystem-style APIs.",
    model:
      "Treat on-disk metadata as an untrusted graph of typed blocks, offsets, checksums, lengths, container relationships, and recovery transitions—not as independent fields.",
    enables: [
      "File-format and recovery-state research",
      "Patch-diff study of recurring metadata bugs",
      "Kernel pool and object-lifetime analysis",
    ],
    checks: [
      "Which metadata blocks are attacker-controlled?",
      "Are offsets and sizes validated before mapping or allocation?",
      "Do recovery and normal paths enforce the same invariants?",
      "Can malformed state survive reopen or reboot?",
    ],
    source:
      "https://splintersfury.github.io/KernelSight/case-studies/clfs-deep-dive/",
    related: [
      "log-transaction-drivers",
      "unsafe-protocol-parsing",
      "patch-diffing",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "ntfs",
    title: "NTFS",
    group: "attack-surfaces",
    summary:
      "NTFS consumes complex on-disk metadata, reparse points, attributes, transactions, oplocks, security descriptors, and namespace operations from local and mounted media.",
    model:
      "Model file records and attributes as a versioned graph with resident/non-resident data, runlists, names, links, indexes, security IDs, and recovery state.",
    enables: [
      "Filesystem parser research",
      "Namespace and reparse analysis",
      "Local or removable-media attack-surface study",
    ],
    checks: [
      "Which attribute or control code reaches the parser?",
      "Are runlists, offsets, and attribute lengths cross-validated?",
      "How do reparse, hard links, and streams affect identity?",
      "Does recovery use partially trusted metadata?",
    ],
    source:
      "https://splintersfury.github.io/KernelSight/case-studies/ntfs-deep-dive/",
    related: ["filesystem-irps", "reparse-points", "filesystem-drivers"],
  }),
  makeConcept({
    slug: "afd",
    title: "AFD and socket kernel interfaces",
    group: "attack-surfaces",
    summary:
      "The Ancillary Function Driver connects Winsock behavior to kernel networking through IOCTL-heavy endpoint, buffer, poll, send, receive, and lifecycle paths.",
    model:
      "Map a user socket operation to its AFD IOCTL, endpoint state, captured buffers, worker or completion path, and network-stack objects. State and concurrency matter as much as packet bytes.",
    enables: [
      "Locally reachable kernel-interface research",
      "Socket state-machine analysis",
      "I/O completion and buffer-lifetime study",
    ],
    checks: [
      "Which socket state is required?",
      "How are user buffers captured and pinned?",
      "Can close or cancellation race pending I/O?",
      "Are counts and array lengths validated together?",
    ],
    source:
      "https://splintersfury.github.io/KernelSight/case-studies/afd-deep-dive/",
    related: ["ndis-network", "ioctl-handlers", "race-conditions"],
  }),
  makeConcept({
    slug: "win32k-attack-surface",
    title: "Win32k and GUI kernel surfaces",
    group: "attack-surfaces",
    summary:
      "GUI, window management, graphics, fonts, menus, input, composition, and cross-process user objects expose a large stateful syscall and callback surface.",
    model:
      "Track user/kernel object pairing, handle tables, desktop and session isolation, locks, callbacks to user mode, object ownership, and historical separation into win32k components.",
    enables: [
      "GUI syscall and object research",
      "Cross-process user-object analysis",
      "Study of user callbacks and manager/worker patterns",
    ],
    checks: [
      "Which session and desktop own the object?",
      "Can a callback reenter while locks or pointers are live?",
      "Are user-mode shadow fields trusted after validation?",
      "Which mitigations changed historical object techniques?",
    ],
    source:
      "https://splintersfury.github.io/KernelSight/case-studies/win32k-deep-dive/",
    related: ["win32k-subsystem", "palette-bitmap-objects", "type-confusion"],
  }),
  makeConcept({
    slug: "io-ring-attack-surface",
    title: "I/O ring attack surface",
    group: "attack-surfaces",
    summary:
      "Windows I/O rings expose asynchronous submission/completion state, registered files and buffers, user/kernel shared structures, and versioned operation validation.",
    model:
      "Treat the ring as a state machine and capability registry. Creation, registration, submission, cancellation, completion, and teardown must agree on ownership and bounds.",
    enables: [
      "Audit new asynchronous I/O paths",
      "Study registered-buffer lifetime",
      "Analyze data-only primitive composition",
    ],
    checks: [
      "Which build and ring version apply?",
      "Who owns registered files and buffers?",
      "Can registration race teardown or mutation?",
      "Which kernel structures are shared, copied, or trusted?",
    ],
    related: ["io-ring", "shared-memory", "race-conditions"],
  }),
  makeConcept({
    slug: "wnf-attack-surface",
    title: "Windows Notification Facility",
    group: "attack-surfaces",
    summary:
      "WNF provides state publication and subscription across scopes and lifetimes, backed by kernel objects, callbacks, state names, and access policy.",
    model:
      "Map state-name ownership, scope, lifetime, security, update/query operations, subscriptions, and teardown. The same mechanism can be an IPC surface and a controlled-allocation building block.",
    enables: [
      "Stateful IPC analysis",
      "Kernel-object lifetime research",
      "Notification and callback race study",
    ],
    checks: [
      "Who can query and update the state?",
      "Which scope and lifetime apply?",
      "Can subscription teardown race delivery?",
      "Are state-data sizes and change stamps validated consistently?",
    ],
    related: ["wnf-state-data", "shared-memory", "race-conditions"],
  }),
  makeConcept({
    slug: "filesystem-namespace-surface",
    title: "Filesystem and namespace operations",
    group: "attack-surfaces",
    summary:
      "Privileged create, copy, move, delete, extract, repair, and cleanup operations repeatedly resolve attacker-influenced paths through Object Manager and filesystem namespaces.",
    model:
      "Trace the final opened handle, not only strings. Record each lookup, reparse, link, parent directory, file ID, volume, owner, DACL, and time-of-check/time-of-use gap.",
    enables: [
      "Find non-memory-corruption LPE",
      "Audit updater and cleanup services",
      "Reason about create/delete/rename conversion",
    ],
    checks: [
      "Can the attacker control any parent directory?",
      "Are paths resolved more than once?",
      "Are final identity and volume checked by handle?",
      "What DACL and owner apply to newly created objects?",
    ],
    related: [
      "object-manager-namespaces",
      "reparse-point-substitution",
      "privileged-file-operations",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "service-control-manager",
    title: "Service Control Manager",
    group: "attack-surfaces",
    summary:
      "The SCM database and service objects expose creation, configuration, security, start/stop, failure action, status, trigger, and custom-control operations across an RPC-backed privileged service.",
    model:
      "Separate SCM rights from per-service rights and filesystem/registry rights. Each handle carries a granted mask; service start later resolves configuration and launches under the configured account.",
    enables: [
      "Audit service-object DACLs",
      "Map configuration-to-execution paths",
      "Find weak binary, DLL, registry, or control-plane permissions",
    ],
    checks: [
      "Which SCM and service access bits are granted?",
      "Who controls binary path, account, parameters, or failure actions?",
      "Can the service be triggered?",
      "Are referenced files and registry values writable?",
    ],
    related: ["service-security", "weak-service-dacl", "service-binary-path"],
  }),
  makeConcept({
    slug: "rpc-services",
    title: "RPC services",
    group: "attack-surfaces",
    summary:
      "Privileged RPC servers expose interface UUIDs, endpoints, bindings, NDR-marshaled methods, context handles, callbacks, authentication levels, and impersonation behavior.",
    model:
      "Build an interface table: endpoint, protocol sequence, method number, input graph, authentication service/level, authorization callback, impersonation point, context lifetime, and privileged side effect.",
    enables: [
      "Recover undocumented service methods",
      "Audit method-level authorization",
      "Find parser, context-handle, and impersonation bugs",
    ],
    checks: [
      "Can a local unprivileged client bind?",
      "Is authentication required and at what level?",
      "Does the server impersonate before resource access?",
      "Can context handles be reused, raced, or confused across clients?",
    ],
    related: ["alpc", "named-pipe-surface", "authorization-bypass"],
    featured: true,
  }),
  makeConcept({
    slug: "com-activation",
    title: "COM and DCOM activation",
    group: "attack-surfaces",
    summary:
      "COM resolves class registration, activation context, server type, AppID policy, proxy/stub marshaling, apartments, elevation, and launch/access permissions before methods execute.",
    model:
      "Map CLSID to InprocServer32 or LocalServer32, optional AppID, activation principal, proxy/stub, moniker or TreatAs redirects, registry view, and the client/server security blanket.",
    enables: [
      "Audit privileged activation paths",
      "Find writable registration and missing-class opportunities",
      "Analyze marshaling and identity boundaries",
    ],
    checks: [
      "Which principal activates the class?",
      "Which registry hive and 32/64-bit view is resolved?",
      "Is the server in-process or out-of-process?",
      "Are launch, access, and method authorization aligned?",
    ],
    related: ["com-hijacking", "rpc-services", "registry-based-primitives"],
  }),
  makeConcept({
    slug: "named-pipe-surface",
    title: "Named-pipe IPC",
    group: "attack-surfaces",
    summary:
      "Named pipes expose filesystem-named server instances, DACLs, connection order, message or byte streams, client identity, impersonation, and remote-access policy.",
    model:
      "Separate name ownership, endpoint DACL, first-instance protection, client authentication, message parsing, impersonation level, and disconnect/reconnect lifetime.",
    enables: [
      "Reach privileged local services",
      "Study impersonation and squatting",
      "Analyze stream framing and connection races",
    ],
    checks: [
      "Can an attacker create the first server instance?",
      "Which clients may connect?",
      "Does the server authenticate the client and vice versa?",
      "Is impersonation reverted on every path?",
    ],
    related: ["named-pipe-impersonation", "named-pipe-objects", "rpc-services"],
  }),
  makeConcept({
    slug: "installer-updater-surface",
    title: "Installers, updaters, repair, and rollback",
    group: "attack-surfaces",
    summary:
      "Privileged maintenance components download, stage, extract, move, delete, restore, register, and execute content across directories often influenced by ordinary users.",
    model:
      "Model the full transaction: source trust, staging ownership, archive paths, signature verification, final-handle validation, rollback state, service stop/start, and cleanup.",
    enables: [
      "Find privileged file-operation LPE",
      "Analyze delete-to-create and rollback conversions",
      "Audit TOCTOU and supply-chain boundaries",
    ],
    checks: [
      "Who owns each staging directory?",
      "When and what is signature-checked?",
      "Are links and reparses rejected at final use?",
      "Can rollback or repair recreate files with attacker-controlled content or security?",
    ],
    related: [
      "privileged-file-copy-restore",
      "installer-rollback",
      "oplock-assisted-race",
    ],
  }),
  makeConcept({
    slug: "process-thread-token-surface",
    title: "Process, thread, job, and token objects",
    group: "attack-surfaces",
    summary:
      "Object handles and native APIs expose process memory, threads, tokens, jobs, sections, debug state, mitigation policy, callbacks, and cross-process operations.",
    model:
      "Start from granted rights. PROCESS_VM_WRITE is different from PROCESS_DUP_HANDLE; TOKEN_DUPLICATE is different from TOKEN_ADJUST_PRIVILEGES. Compose only operations unlocked by the actual mask.",
    enables: [
      "Audit handle leaks and duplication",
      "Study token and impersonation paths",
      "Map injection and protected-process boundaries",
    ],
    checks: [
      "Which exact access mask is granted?",
      "Can a privileged handle be inherited or duplicated?",
      "Which process protection and mitigation policy applies?",
      "Does the operation cross session, integrity, or PPL boundaries?",
    ],
    related: [
      "handles-and-access-masks",
      "access-tokens",
      "handle-acquisition",
    ],
  }),
];
