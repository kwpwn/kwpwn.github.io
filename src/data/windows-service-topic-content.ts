export interface WindowsServiceTopicContent {
  slug: string;
  category: string;
  eyebrow: string;
  summary: string;
  boundary: string;
  whyItMatters: string;
  weaknessPatterns: Array<{ title: string; detail: string }>;
  auditQuestions: string[];
  labWorkflow: string[];
  relatedConcepts: Array<{ label: string; href: string }>;
}

export const windowsServiceTopicContent: WindowsServiceTopicContent[] = [
  {
    slug: "deployment-maintenance",
    category: "Deployment & maintenance",
    eyebrow: "Installers, updates, orchestration, and repair",
    summary:
      "Privileged deployment services transform packages, manifests, policy, and recovery state into filesystem, registry, service, and reboot-time changes. Their security depends on preserving the caller's authority and the identity of every object from validation through commit.",
    boundary:
      "An unprivileged user, remote management client, package publisher, or partially trusted application supplies work to a SYSTEM service that can install binaries, create services, rewrite protected paths, schedule actions, and survive reboots. Temporary directories, rollback journals, package caches, RPC endpoints, and repair callbacks all cross that boundary.",
    whyItMatters:
      "A narrow path or authorization mistake can become a durable elevation primitive because deployment engines already own the exact capabilities an attacker normally needs to manufacture. Exploitation often uses legitimate recovery behavior rather than direct memory corruption, so the final action can look like ordinary maintenance unless object identity and provenance are audited.",
    weaknessPatterns: [
      {
        title: "Privileged file operation",
        detail:
          "A user-controlled source, destination, reparse point, hard link, or rollback path is consumed by a service with write, move, delete, restore, or ACL-changing authority.",
      },
      {
        title: "Package trust confusion",
        detail:
          "Signature, publisher, applicability, or catalog validation is performed on a different object or representation from the one later staged or executed.",
      },
      {
        title: "TOCTOU in staging",
        detail:
          "The service validates a path or handle and later reopens it by name, allowing a junction, mount point, rename, or content swap to redirect the privileged operation.",
      },
      {
        title: "Unsafe custom action",
        detail:
          "Installer or repair metadata crosses into command construction, environment expansion, DLL loading, COM activation, or child-process creation without a strict authority check.",
      },
      {
        title: "Rollback and reboot abuse",
        detail:
          "Deferred cleanup, recovery journals, failure actions, or PendingFileRenameOperations preserve attacker influence after the original validation context has disappeared.",
      },
    ],
    auditQuestions: [
      "Which callers can submit, repair, cancel, or resume deployment work?",
      "Are source and destination objects held by handle across validation and commit?",
      "Can a user modify any parent directory, reparse point, package cache, or rollback artifact?",
      "Which package fields reach command lines, service configuration, registry paths, or DLL resolution?",
      "Does reboot or service restart process state created in a weaker security context?",
      "Are impersonation, publisher checks, and policy decisions repeated at the final privileged sink?",
    ],
    labWorkflow: [
      "Snapshot a disposable VM and record the service account, executable, SCM names, RPC/COM surface, and writable package locations.",
      "Trace a legitimate install, update, repair, uninstall, and failed rollback with Procmon and ETW while preserving timestamps and object paths.",
      "Replace path-based assumptions with controlled junction, hard-link, rename, oplock, and content-swap experiments one boundary at a time.",
      "Confirm the final access token, requested access mask, object identity, and resulting ACL before treating behavior as a primitive.",
      "Repeat across affected and fixed builds, then compare binaries, manifests, policy, and object-open flags to identify the security invariant Microsoft added.",
    ],
    relatedConcepts: [
      {
        label: "Installer and updater attack surface",
        href: "/windows-security-concepts/installer-updater-surface/",
      },
      {
        label: "Privileged file operations",
        href: "/windows-security-concepts/privileged-file-operations/",
      },
      {
        label: "Oplock-assisted races",
        href: "/windows-security-concepts/oplock-assisted-race/",
      },
    ],
  },
  {
    slug: "discovery-services",
    category: "Discovery services",
    eyebrow: "Presence, naming, and device discovery",
    summary:
      "Discovery services turn unauthenticated or weakly authenticated network announcements into local names, endpoints, devices, and follow-on connections. The dangerous transition is rarely the announcement alone; it is the privileged parser or automatic client behavior that trusts what was discovered.",
    boundary:
      "A nearby network peer, multicast sender, local application, or virtual network participant supplies packets and metadata to long-running services. Those services parse variable-length protocol structures, update shared caches, expose local RPC state, and may cause higher-level clients to fetch resources or authenticate to an advertised endpoint.",
    whyItMatters:
      "Discovery is intentionally permissive and often enabled before a machine has established strong network trust. A parser flaw can therefore be pre-authentication RCE or denial of service, while a logic flaw can redirect credentials and administrative tools toward attacker-controlled infrastructure.",
    weaknessPatterns: [
      {
        title: "Unauthenticated packet parsing",
        detail:
          "Multicast, broadcast, or link-local messages reach native parsers before identity, network profile, or policy can reduce the attack surface.",
      },
      {
        title: "Length and state mismatch",
        detail:
          "Nested record lengths, compression, fragmentation, duplicate fields, or cache lifetime rules disagree across parser stages and produce out-of-bounds access or stale objects.",
      },
      {
        title: "Name-to-endpoint confusion",
        detail:
          "A discovered friendly name, URI, address family, scope, or canonical form is trusted as though it proved endpoint identity.",
      },
      {
        title: "Credential redirection",
        detail:
          "Automatic follow-on access to an advertised share, proxy, printer, or management endpoint causes privileged or domain credentials to leave the host.",
      },
      {
        title: "Cache poisoning and persistence",
        detail:
          "Untrusted discovery data survives longer than its authentication context and influences later clients, network profiles, or device installation.",
      },
    ],
    auditQuestions: [
      "Which interfaces and network profiles receive discovery traffic by default?",
      "What input reaches native parsing before authentication or policy evaluation?",
      "How are nested lengths, compression pointers, fragments, duplicates, and cache expiry validated?",
      "Can an announcement trigger SMB, HTTP, RPC, driver installation, or credential-bearing traffic?",
      "Are discovered names canonicalized and bound cryptographically to the selected endpoint?",
      "Does cache state cross users, interfaces, sleep/resume, or network-profile changes?",
    ],
    labWorkflow: [
      "Isolate two VMs on a host-only network and capture a normal discovery exchange before mutating fields.",
      "Map the receiving process, service trigger, firewall rule, parser module, and downstream client behavior.",
      "Replay one structural mutation at a time while collecting ETW, packet captures, verifier output, and crash dumps.",
      "Test whether advertisements cause outbound authentication or privileged resource access without user confirmation.",
      "Compare fixed builds for bounds checks, canonicalization, cache-key, and authentication changes.",
    ],
    relatedConcepts: [
      {
        label: "Unsafe protocol parsing",
        href: "/windows-security-concepts/unsafe-protocol-parsing/",
      },
      {
        label: "Network stack drivers",
        href: "/windows-security-concepts/network-stack-drivers/",
      },
      {
        label: "Runtime tracing",
        href: "/windows-security-concepts/runtime-tracing/",
      },
    ],
  },
  {
    slug: "file-print-services",
    category: "File & print services",
    eyebrow: "Shares, namespaces, spoolers, and document pipelines",
    summary:
      "File and print services translate remote identities, paths, document formats, drivers, and asynchronous jobs into privileged kernel and user-mode operations. They combine broad reachability with complex legacy protocols and are frequent starting points for remote execution, credential coercion, and local privilege escalation.",
    boundary:
      "Remote clients and local low-privilege users submit names, share paths, printer objects, job data, drivers, and callbacks to services that impersonate clients while also performing SYSTEM operations. The boundary crosses SMB/RPC transports, filesystem namespaces, spool directories, provider DLLs, and kernel redirectors.",
    whyItMatters:
      "These services are designed to move attacker-shaped bytes and object names between machines. A single missed authorization check or path transition can expose domain credentials, install code, overwrite protected files, or compromise every host that accepts the same administrative workflow.",
    weaknessPatterns: [
      {
        title: "Pre-authentication protocol bug",
        detail:
          "Negotiation, compression, transaction, or message parsing corrupts memory before a client identity is established.",
      },
      {
        title: "Impersonation gap",
        detail:
          "A method validates while impersonating but performs a later filesystem, registry, driver, or network action after reverting to SYSTEM.",
      },
      {
        title: "Namespace redirection",
        detail:
          "UNC paths, device paths, reparse points, provider prefixes, or canonicalization differences redirect a privileged operation.",
      },
      {
        title: "Driver or provider loading",
        detail:
          "Remote or local configuration influences which DLL, print processor, port monitor, provider, or driver is loaded into a privileged process.",
      },
      {
        title: "Authentication coercion",
        detail:
          "A service accepts a remote path or callback endpoint and authenticates to it with machine or service credentials that can be relayed.",
      },
    ],
    auditQuestions: [
      "Which methods are reachable before authentication and which require only ordinary domain membership?",
      "Where does the service impersonate, revert, duplicate tokens, or queue work for another thread?",
      "Can user-controlled paths cross UNC, NT, Win32, provider, spool, or reparse namespaces?",
      "Which configuration fields select executable modules or downstream protocol handlers?",
      "Can any method force outbound authentication to an arbitrary host or service class?",
      "Are spool, cache, temporary, and job objects isolated by user and protected across restart?",
    ],
    labWorkflow: [
      "Capture a normal share, print job, driver query, and administrative operation with network and local traces.",
      "Resolve every RPC method, named pipe, SMB command, provider module, and impersonation transition in the chain.",
      "Exercise path forms and callback endpoints in a lab domain while monitoring outbound credentials and object opens.",
      "Use verifier and page heap only on disposable systems to distinguish parser corruption from authorization or namespace bugs.",
      "Patch-diff the service, protocol DLL, provider, redirector, and policy changes together rather than assuming one binary owns the fix.",
    ],
    relatedConcepts: [
      {
        label: "Filesystem namespace surface",
        href: "/windows-security-concepts/filesystem-namespace-surface/",
      },
      {
        label: "Named-pipe impersonation",
        href: "/windows-security-concepts/named-pipe-impersonation/",
      },
      {
        label: "RPC services",
        href: "/windows-security-concepts/rpc-services/",
      },
    ],
  },
  {
    slug: "ipc-management",
    category: "IPC & management",
    eyebrow: "RPC, COM, WMI, remoting, and administrative brokers",
    summary:
      "Management services expose powerful operating-system actions through RPC, COM, WMI, named pipes, ALPC, and remoting protocols. Their central question is not whether the caller can connect, but whether each method authorizes the exact object and side effect requested.",
    boundary:
      "Local applications, sandboxed processes, remote administrators, and ordinary domain users call brokers running as SYSTEM, Network Service, or a privileged service account. Parameters are marshaled across process, session, integrity, machine, and sometimes tenant boundaries before reaching native APIs.",
    whyItMatters:
      "A management interface can expose process creation, file operations, registry changes, service control, credential use, or remote callbacks by design. Authorization bypasses and confused-deputy bugs therefore create high-quality primitives even when memory safety is intact.",
    weaknessPatterns: [
      {
        title: "Method-level authorization gap",
        detail:
          "The endpoint is protected, but an individual opnum, COM method, namespace, or object identifier lacks the access check required for its side effect.",
      },
      {
        title: "Confused deputy",
        detail:
          "The broker trusts process identity, a handle supplied by another component, or a frontend assertion instead of authorizing the requesting security principal.",
      },
      {
        title: "Marshalling and type confusion",
        detail:
          "NDR, VARIANT, SAFEARRAY, object reference, or custom message state is interpreted under inconsistent type, size, or lifetime assumptions.",
      },
      {
        title: "Impersonation discontinuity",
        detail:
          "Work is queued, retried, delegated, or callback-driven after the original caller token has been lost or replaced.",
      },
      {
        title: "Object binding failure",
        detail:
          "A checked name, PID, handle, moniker, namespace, or session identifier is not bound to the object acted on later.",
      },
    ],
    auditQuestions: [
      "Enumerate every interface, endpoint, opnum, COM class, WMI namespace, and named pipe—not only documented methods.",
      "What security descriptor protects connection, activation, and each sensitive method?",
      "Is authorization based on the caller token and requested object, or on a trusted process/frontend label?",
      "Where can asynchronous work, callbacks, retries, or cross-service calls lose impersonation context?",
      "Which variable-length or polymorphic types cross custom marshalling code?",
      "Can a caller substitute a PID, handle, path, moniker, session, or callback endpoint after validation?",
    ],
    labWorkflow: [
      "Enumerate interfaces with public symbols, RPC/COM tooling, WMI metadata, ETW, and endpoint inspection.",
      "Record method calls from legitimate clients and map parameters to server-side authorization and privileged sinks.",
      "Replay calls from tokens with systematically reduced groups, privileges, integrity levels, sessions, and network identities.",
      "Stress asynchronous lifetime and object-binding transitions before attempting any exploit chain.",
      "Compare fixed builds for new access checks, impersonation scopes, object references, and marshalling validation.",
    ],
    relatedConcepts: [
      {
        label: "RPC/COM confused deputy",
        href: "/windows-security-concepts/rpc-com-confused-deputy/",
      },
      {
        label: "COM activation",
        href: "/windows-security-concepts/com-activation/",
      },
      { label: "ALPC", href: "/windows-security-concepts/alpc/" },
    ],
  },
  {
    slug: "identity-directory",
    category: "Identity & directory",
    eyebrow:
      "Authentication, authorization, directory, and credential services",
    summary:
      "Identity services decide who a principal is, which credentials and tickets are valid, and what that identity may access across a Windows estate. Protocol parsing, cryptographic validation, directory ACLs, delegation, and policy all participate in one security decision.",
    boundary:
      "Unauthenticated network clients, domain members, trusted domains, local logon packages, certificate holders, and administrators submit credentials, claims, directory operations, and policy changes to services that control tokens and enterprise trust. Replication and delegation extend the boundary beyond one host.",
    whyItMatters:
      "Failures can bypass authentication, expose credentials, forge identity, elevate directory rights, or compromise a domain. Even a read-only disclosure may reveal keys or topology that changes the feasibility of a broader chain.",
    weaknessPatterns: [
      {
        title: "Authentication state confusion",
        detail:
          "Negotiation, pre-authentication, channel binding, downgrade, or multi-step state is accepted out of order or bound to the wrong connection or principal.",
      },
      {
        title: "Cryptographic validation gap",
        detail:
          "Signatures, tickets, certificates, hashes, nonces, algorithms, or canonical encodings are incompletely checked before identity is accepted.",
      },
      {
        title: "Directory ACL and delegation bug",
        detail:
          "An ordinary principal can create, modify, link, enroll, delegate, replicate, or reset an object with security consequences beyond the granted right.",
      },
      {
        title: "Parser and decompression flaw",
        detail:
          "ASN.1, NDR, LDAP filters, claims, PAC data, certificates, or replication structures reach complex native parsers across the network.",
      },
      {
        title: "Credential exposure or relay",
        detail:
          "Secrets, hashes, tickets, tokens, or machine authentication are disclosed or sent to an attacker-controlled service without adequate binding.",
      },
    ],
    auditQuestions: [
      "Which protocol states are reachable without credentials, with expired credentials, or from an untrusted domain?",
      "Are identity, channel, target name, algorithm, and transcript cryptographically bound together?",
      "Which directory rights indirectly grant enrollment, delegation, replication, password reset, or code execution?",
      "Can canonicalization differences change a principal, SPN, DN, certificate name, or policy target?",
      "Where are credentials materialized, cached, logged, exported, or forwarded to another service?",
      "Do replication, trust, and compatibility paths enforce the same checks as the primary path?",
    ],
    labWorkflow: [
      "Build a disposable multi-host domain with a subordinate ordinary user and preserve domain-controller snapshots.",
      "Capture successful and failed authentication, directory modification, certificate, and delegation workflows.",
      "Model object ownership and effective ACLs before changing protocol fields or directory attributes.",
      "Use negative tests for channel binding, target naming, replay, downgrade, trust direction, and canonical forms.",
      "Validate fixes across client and server builds because identity protections are often negotiated and only effective when both sides participate.",
    ],
    relatedConcepts: [
      {
        label: "Access tokens",
        href: "/windows-security-concepts/access-tokens/",
      },
      {
        label: "Security descriptors",
        href: "/windows-security-concepts/security-descriptors/",
      },
      {
        label: "Access checks",
        href: "/windows-security-concepts/access-checks/",
      },
    ],
  },
  {
    slug: "network-services",
    category: "Network services",
    eyebrow: "Core protocol stacks, listeners, and routing services",
    summary:
      "Network services consume attacker-controlled packets at high privilege and often before application authentication. The attack surface spans kernel transports, protocol drivers, shared libraries, service hosts, firewall policy, and user-mode listeners.",
    boundary:
      "Remote peers and adjacent networks provide frames, packets, fragments, options, names, and connection state to parsers running in the kernel or privileged services. Hardware offload, tunneling, virtualization, and compatibility layers can create alternate routes to the same logic.",
    whyItMatters:
      "Reachability can be broad and interaction minimal, so memory corruption may become wormable RCE while state or resource bugs can cause fleet-wide denial of service. Configuration and firewall exposure must be analyzed alongside the code flaw.",
    weaknessPatterns: [
      {
        title: "Length and integer error",
        detail:
          "Header, option, fragment, compression, or reassembly arithmetic allocates one size and copies or indexes using another.",
      },
      {
        title: "State-machine violation",
        detail:
          "Unexpected ordering, retransmission, teardown, timeout, or cross-connection reuse reaches logic that assumes a completed handshake.",
      },
      {
        title: "Lifetime and concurrency bug",
        detail:
          "Packet processing, timers, cancellation, offload, and connection teardown race over reference-counted state.",
      },
      {
        title: "Policy or binding bypass",
        detail:
          "Interface, profile, compartment, namespace, source, destination, or authentication state is lost before firewall or authorization policy is applied.",
      },
      {
        title: "Resource exhaustion",
        detail:
          "Unauthenticated work allocates nonpaged pool, queues, fragments, handles, threads, or cryptographic state without an enforceable per-peer budget.",
      },
    ],
    auditQuestions: [
      "Which ports, protocols, interfaces, profiles, compartments, and tunnel paths reach the code by default?",
      "Where do arithmetic and buffer ownership change across kernel, driver, and user-mode boundaries?",
      "How are fragments, options, retransmissions, cancellation, timeout, and teardown synchronized?",
      "Can hardware offload or virtualization bypass validation performed on the ordinary software path?",
      "What unauthenticated resources are charged, and to which peer or security principal?",
      "Does mitigation guidance actually remove reachability, or only reduce one advertised route?",
    ],
    labWorkflow: [
      "Map packet reachability with firewall state, listeners, ETW providers, WFP layers, drivers, and service triggers.",
      "Capture a minimal valid exchange and mutate structure, ordering, fragmentation, and timing independently.",
      "Collect kernel dumps, pool usage, verifier telemetry, packet captures, and service state on isolated VMs.",
      "Test physical, virtual, tunneled, loopback, IPv4/IPv6, and offload variants when the affected component supports them.",
      "Diff all owning binaries and drivers, then verify whether the fix changes validation, lifetime, accounting, or default exposure.",
    ],
    relatedConcepts: [
      {
        label: "NDIS and network surface",
        href: "/windows-security-concepts/ndis-network/",
      },
      {
        label: "Buffer overflow",
        href: "/windows-security-concepts/buffer-overflow/",
      },
      {
        label: "Reference-counting bugs",
        href: "/windows-security-concepts/reference-counting-bugs/",
      },
    ],
  },
  {
    slug: "remote-access",
    category: "Remote access",
    eyebrow: "Interactive sessions, gateways, VPN, and remote administration",
    summary:
      "Remote-access services accept complex pre-authentication negotiation and then create high-trust interactive or tunneled sessions. Graphics, device redirection, clipboard, filesystem, audio, smart-card, gateway, and VPN channels dramatically expand the parser and authorization surface.",
    boundary:
      "Internet or enterprise clients negotiate transport, security, authentication, capabilities, virtual channels, and session state with gateways and services that can create logon sessions or bridge networks. Some inputs continue into kernel drivers and third-party codecs after authentication.",
    whyItMatters:
      "A pre-authentication flaw can expose perimeter servers; a post-authentication flaw may let a low-privilege user escape a session boundary or attack an administrator. Redirection and gateway logic can also leak credentials or cross network segmentation without memory corruption.",
    weaknessPatterns: [
      {
        title: "Pre-authentication negotiation bug",
        detail:
          "Transport, security-layer, capability, cookie, gateway, or authentication messages reach complex code before a user identity is established.",
      },
      {
        title: "Virtual-channel parser flaw",
        detail:
          "Clipboard, drive, printer, graphics, audio, smart-card, or custom channel messages carry nested attacker-controlled structures across process boundaries.",
      },
      {
        title: "Session isolation failure",
        detail:
          "Handles, windows, objects, devices, namespaces, tokens, or cached state are confused across users or sessions.",
      },
      {
        title: "Gateway trust confusion",
        detail:
          "The system authenticates the gateway, backend, client, or target name incompletely and forwards credentials or traffic under the wrong trust assumption.",
      },
      {
        title: "Resource and reconnect race",
        detail:
          "Disconnect, reconnect, roaming, cancellation, or session teardown leaves stale objects or cross-session state.",
      },
    ],
    auditQuestions: [
      "Which parsing and capability paths execute before authentication and network-level authentication?",
      "What code owns every virtual channel and which token/session processes its requests?",
      "Are backend target, gateway, certificate, SPN, and user intent bound to the same authenticated transcript?",
      "Can redirection access local devices, files, credentials, or network routes beyond the session policy?",
      "How are reconnect, shadowing, fast user switching, cancellation, and teardown synchronized?",
      "Do policy mitigations disable the vulnerable parser or merely hide the normal UI path?",
    ],
    labWorkflow: [
      "Create isolated client, target, and gateway VMs and record the complete connection sequence at each hop.",
      "Enumerate enabled capabilities and virtual channels before fuzzing the smallest valid message for one channel.",
      "Trace process, driver, token, session, and object-namespace transitions for redirected operations.",
      "Exercise disconnect/reconnect and gateway/backend identity changes while preserving network and crash evidence.",
      "Retest with affected and fixed clients as well as servers because negotiated protections can depend on both endpoints.",
    ],
    relatedConcepts: [
      {
        label: "Process, thread, and token surface",
        href: "/windows-security-concepts/process-thread-token-surface/",
      },
      {
        label: "Named-pipe surface",
        href: "/windows-security-concepts/named-pipe-surface/",
      },
      {
        label: "Research evidence",
        href: "/windows-security-concepts/research-evidence/",
      },
    ],
  },
  {
    slug: "security-services",
    category: "Security services",
    eyebrow: "Endpoint protection, policy enforcement, and inspection",
    summary:
      "Security services deliberately inspect hostile files, scripts, memory, telemetry, and network content while holding exceptional privileges and self-protection authority. Their parser surface and trusted frontend/backend relationships require the same scrutiny as any other privileged broker.",
    boundary:
      "Untrusted content, ordinary users, management consoles, cloud policy, and cooperating drivers feed engines and services that can quarantine files, terminate processes, inject scanning components, change policy, and resist tampering. Trust crosses user mode, kernel callbacks, filter drivers, cloud verdicts, and update channels.",
    whyItMatters:
      "An engine parser flaw can be triggered by merely scanning content, while authorization and quarantine bugs can turn defensive actions into arbitrary file or process primitives. Because the component is ubiquitous and highly trusted, failures can invalidate several layers of defense at once.",
    weaknessPatterns: [
      {
        title: "Scan-on-access parser bug",
        detail:
          "A crafted archive, document, script, executable, metadata stream, or protocol object reaches native parsing automatically in a privileged context.",
      },
      {
        title: "Trusted frontend confusion",
        detail:
          "A backend authorizes commands because they originate from a named process or UI channel that a user can influence through COM, DLL loading, injection, or message replay.",
      },
      {
        title: "Quarantine file primitive",
        detail:
          "Detection, remediation, delayed deletion, restore, or exclusion processing follows attacker-controlled paths or stale object identities.",
      },
      {
        title: "Self-protection authorization gap",
        detail:
          "A local caller can disable policy, unload a component, terminate a protected process, alter exclusions, or invoke a privileged diagnostic operation.",
      },
      {
        title: "Update and trust-chain failure",
        detail:
          "Engine, signature, model, plugin, or policy updates are accepted or applied under weaker integrity or rollback rules than the main product.",
      },
    ],
    auditQuestions: [
      "Which content types are scanned automatically and in which process, sandbox, token, or driver context?",
      "Does a backend authenticate the caller principal and request, or only a trusted process image/frontend?",
      "Are quarantine and restore objects held by handle across detection, user action, restart, and reboot?",
      "Which local users can change exclusions, policy, diagnostics, update channels, or remediation actions?",
      "Can security callbacks race process, handle, file, or image creation and leave an unprotected interval?",
      "Are updates protected against downgrade, replay, partial replacement, and cross-channel confusion?",
    ],
    labWorkflow: [
      "Use only inert test artifacts and a disposable VM; never feed unknown public PoCs to a production endpoint.",
      "Map engine, service, UI, cloud, update, and driver communication before testing individual commands.",
      "Trace detection through quarantine, reboot cleanup, restore, exclusion, and policy propagation with object identities preserved.",
      "Test caller identity and message replay from ordinary processes without weakening host-wide protections outside the lab.",
      "Compare engine/signature versions and platform builds separately so the owning fix is attributed correctly.",
    ],
    relatedConcepts: [
      {
        label: "Third-party security drivers",
        href: "/windows-security-concepts/third-party-security-drivers/",
      },
      {
        label: "Protected Process Light",
        href: "/windows-security-concepts/protected-process-light/",
      },
      {
        label: "TOCTOU and double fetch",
        href: "/windows-security-concepts/toctou-double-fetch/",
      },
    ],
  },
  {
    slug: "storage-devices",
    category: "Storage & devices",
    eyebrow:
      "Volumes, backup, removable media, peripherals, and device brokers",
    summary:
      "Storage and device services convert user and remote requests into volume, snapshot, backup, mount, media, and hardware operations. They sit above kernel drivers but often retain enough authority to expose physical resources, rewrite protected data, or load device-specific code.",
    boundary:
      "Local users, backup clients, removable devices, network peers, applications, and management tools provide paths, descriptors, images, metadata, and I/O requests to SYSTEM services and kernel stacks. Object namespaces, device interfaces, IOCTLs, RPC, Plug and Play, and filter drivers all participate.",
    whyItMatters:
      "The intended capability is already close to an exploitation primitive: mounting, snapshotting, restoring, mapping, formatting, or issuing device commands. Weak authorization or object binding can expose protected files, raw storage, kernel memory, or persistence paths.",
    weaknessPatterns: [
      {
        title: "Weak device or RPC ACL",
        detail:
          "An ordinary caller can open a control interface or invoke a method whose access mask is sufficient for privileged storage or device operations.",
      },
      {
        title: "Image and metadata parser bug",
        detail:
          "Filesystem, archive, backup, media, descriptor, or device metadata reaches complex native parsers in services or drivers.",
      },
      {
        title: "Snapshot and restore confusion",
        detail:
          "A caller can read, restore, expose, or redirect data outside the authorized volume, writer, application, or user boundary.",
      },
      {
        title: "Path-to-device substitution",
        detail:
          "DOS, NT, volume GUID, device-interface, mount-point, reparse, or symbolic-link names resolve to a different object at use time.",
      },
      {
        title: "Privileged IOCTL proxy",
        detail:
          "A service validates a high-level request but forwards attacker-controlled buffers, addresses, commands, or handles to a more privileged driver.",
      },
    ],
    auditQuestions: [
      "Which users can open each device interface, RPC endpoint, named pipe, or management object and with what access?",
      "What image, filesystem, media, backup, or descriptor formats are parsed before trust is established?",
      "Can snapshots, backups, mounts, and restores cross volume, user, container, or application boundaries?",
      "Are paths resolved once to handles, or repeatedly through mutable namespace components?",
      "Which request fields reach IOCTLs, SCSI/NVMe commands, physical mappings, or driver handles?",
      "How do surprise removal, cancellation, sleep, resume, and service restart affect object lifetime?",
    ],
    labWorkflow: [
      "Inventory services, drivers, device interfaces, symbolic links, RPC methods, and ACLs on a snapshot-backed VM.",
      "Capture normal mount, snapshot, backup, restore, device arrival, and removal paths before mutation.",
      "Test namespace and object-binding transitions with benign files and virtual disks rather than real user data.",
      "Trace high-level service requests into IOCTLs and confirm whether the driver repeats authorization and bounds checks.",
      "Diff service and driver fixes together and retest cancellation, teardown, and restart paths.",
    ],
    relatedConcepts: [
      {
        label: "Weak device DACL",
        href: "/windows-security-concepts/weak-device-dacl/",
      },
      {
        label: "Direct IOCTL read/write",
        href: "/windows-security-concepts/direct-ioctl-read-write/",
      },
      {
        label: "PnP and power",
        href: "/windows-security-concepts/pnp-and-power/",
      },
    ],
  },
  {
    slug: "system-services",
    category: "System services",
    eyebrow:
      "Core brokers, schedulers, logging, policy, and host infrastructure",
    summary:
      "System services provide cross-cutting operating-system functions such as scheduling, logging, licensing, cryptography, profile management, service control, diagnostics, and session coordination. Their interfaces are often local, but the privilege difference between caller and service makes them rich elevation targets.",
    boundary:
      "Ordinary applications, users, sandboxed processes, administrators, and other services submit configuration, files, handles, callbacks, jobs, and object identifiers to long-running privileged brokers. Many share svchost processes, registry state, RPC endpoints, and boot or logon lifecycle hooks.",
    whyItMatters:
      "These brokers persist across sessions and frequently convert declarative state into later privileged actions. Authorization, service DACL, path, token, and object-lifetime mistakes can yield reliable local escalation or security-feature bypass without a traditional memory-corruption exploit.",
    weaknessPatterns: [
      {
        title: "Weak service configuration ACL",
        detail:
          "A user can start, stop, reconfigure, replace, or influence a privileged service through its DACL, registry parameters, binary path, DLL path, or failure actions.",
      },
      {
        title: "Scheduled or deferred action confusion",
        detail:
          "A job, event, log, task, notification, or reboot-time action is validated in one context and executed later with broader authority.",
      },
      {
        title: "Token and handle misuse",
        detail:
          "The service duplicates, impersonates, inherits, caches, or looks up a token or handle without binding it to the authorized caller and target.",
      },
      {
        title: "Local IPC memory corruption",
        detail:
          "RPC, ALPC, named-pipe, registry, or custom message structures expose native parsing and lifetime errors to low-integrity callers.",
      },
      {
        title: "Policy and state canonicalization",
        detail:
          "Registry views, object names, sessions, profiles, locales, or identifiers are normalized differently between validation and enforcement.",
      },
    ],
    auditQuestions: [
      "What do the service object, executable, DLLs, registry keys, IPC endpoints, and writable directories permit ordinary users to change?",
      "Which requests are stored and executed after logon, reboot, failure, timer, or another service callback?",
      "Where are caller tokens, privileges, sessions, PIDs, and handles captured and revalidated?",
      "Can low-integrity or AppContainer callers reach undocumented methods or shared host state?",
      "Do path, registry, object-manager, locale, and session canonicalization agree at every decision point?",
      "Could compromising one service in a shared host change the authority or state of its neighbors?",
    ],
    labWorkflow: [
      "Enumerate SCM configuration, service and registry DACLs, host groups, triggers, endpoints, writable paths, and loaded modules.",
      "Trace a legitimate request from client API through IPC, token transition, deferred storage, and final privileged sink.",
      "Repeat with low-integrity, AppContainer, standard-user, service, and alternate-session tokens.",
      "Exercise restart, failure, logon, reboot, cancellation, and concurrent-client paths while tracking object identity.",
      "Compare fixed builds for new access checks, handle-based operations, canonicalization, and lifecycle cleanup.",
    ],
    relatedConcepts: [
      {
        label: "Service security",
        href: "/windows-security-concepts/service-security/",
      },
      {
        label: "Weak service DACL",
        href: "/windows-security-concepts/weak-service-dacl/",
      },
      {
        label: "Service Control Manager",
        href: "/windows-security-concepts/service-control-manager/",
      },
    ],
  },
  {
    slug: "virtualization-containers",
    category: "Virtualization & containers",
    eyebrow: "Hyper-V, host compute, isolation, and synthetic devices",
    summary:
      "Virtualization and container services enforce boundaries between guests, containers, utility VMs, management clients, and the Windows host. The surface includes hypercalls, synthetic devices, virtual switches, storage, saved state, management RPC, and host-compute orchestration.",
    boundary:
      "A guest kernel, container process, remote management client, image publisher, or local tenant supplies descriptors, device traffic, configuration, and state to the hypervisor, kernel drivers, worker processes, and SYSTEM management services. Trust differs substantially between process, Hyper-V, and VBS isolation.",
    whyItMatters:
      "A successful escape crosses one of the platform's strongest advertised boundaries and can expose other tenants or the host. Management-plane authorization bugs can be equally serious because they create, attach, snapshot, or reconfigure isolated workloads by design.",
    weaknessPatterns: [
      {
        title: "Synthetic-device memory corruption",
        detail:
          "Guest-controlled ring, descriptor, packet, graphics, storage, or integration-service data reaches host parsers with complex lifetime and size assumptions.",
      },
      {
        title: "Hypercall or partition validation gap",
        detail:
          "Addresses, handles, VP state, permissions, or partition ownership are checked incompletely before the hypervisor or kernel performs an operation.",
      },
      {
        title: "Management-plane authorization",
        detail:
          "A local or remote caller can create, open, attach, snapshot, mount, configure, or execute against a workload it does not own.",
      },
      {
        title: "Saved-state and image parser bug",
        detail:
          "Checkpoint, migration, container layer, utility-VM, registry hive, or configuration formats are parsed with host authority.",
      },
      {
        title: "Isolation-mode confusion",
        detail:
          "Code assumes process, Hyper-V, VBS, or administrator trust properties that are not true for the selected workload configuration.",
      },
    ],
    auditQuestions: [
      "Which guest-controlled bytes reach the hypervisor, host kernel, worker process, integration service, or management service?",
      "Are guest addresses, ring indices, descriptors, handles, and partition ownership revalidated after every asynchronous transition?",
      "Which principals can manage, attach to, snapshot, mount, or import each workload?",
      "What saved-state, image, configuration, and migration data is parsed outside the guest boundary?",
      "Do process and Hyper-V isolated containers take materially different code paths or authority decisions?",
      "How do live migration, checkpoint, teardown, reset, and host sleep affect shared-object lifetime?",
    ],
    labWorkflow: [
      "Use a dedicated virtualization host with no valuable workloads and preserve host and guest snapshots.",
      "Map the boundary from guest action to VMBus, device backend, worker process, driver, hypercall, and management RPC.",
      "Capture one valid descriptor or management operation and mutate size, ownership, ordering, cancellation, and teardown separately.",
      "Test equivalent process-isolated, Hyper-V-isolated, Generation 1/2, and configuration-version paths only when applicable.",
      "Collect host dumps and patch-diff every owning hypervisor, driver, worker, and management component before attributing a fix.",
    ],
    relatedConcepts: [
      {
        label: "DMA and MMIO access",
        href: "/windows-security-concepts/dma-mmio-access/",
      },
      { label: "VBS and HVCI", href: "/windows-security-concepts/vbs-hvci/" },
      {
        label: "Shared memory",
        href: "/windows-security-concepts/shared-memory/",
      },
    ],
  },
  {
    slug: "web-messaging",
    category: "Web & messaging",
    eyebrow: "HTTP servers, queues, messaging, and web administration",
    summary:
      "Web and messaging services accept structured remote content, route it through protocol stacks and queues, and frequently invoke application or administrative handlers. HTTP.sys, IIS components, message queuing, WebDAV, and related brokers mix internet reachability with deep legacy behavior.",
    boundary:
      "Remote clients, authenticated applications, queue senders, reverse proxies, and administrators provide requests, headers, paths, bodies, certificates, messages, and configuration to kernel and user-mode services. Requests may cross HTTP.sys, worker processes, protocol modules, queues, filesystem handlers, and management APIs.",
    whyItMatters:
      "Pre-authentication parser bugs can compromise exposed servers, while request-routing, queue, path, and management flaws can cross application pools or execute with service authority. Message persistence means malicious input can trigger later and on another node.",
    weaknessPatterns: [
      {
        title: "Request parser discrepancy",
        detail:
          "Kernel, proxy, server, module, and application disagree on header, chunking, encoding, path, length, or request boundaries.",
      },
      {
        title: "Queue message memory corruption",
        detail:
          "Remote or local messages contain nested properties, routing, transaction, serialization, or fragmentation state consumed by native parsers.",
      },
      {
        title: "Path and handler confusion",
        detail:
          "URL decoding, canonicalization, alternate streams, virtual directories, WebDAV, or handler mapping resolves to unintended content or executable behavior.",
      },
      {
        title: "Cross-tenant routing or authorization",
        detail:
          "Host headers, bindings, application pools, queue names, certificates, or management identifiers are not bound to the authorized tenant or principal.",
      },
      {
        title: "Persistent asynchronous trigger",
        detail:
          "A queued, retried, dead-lettered, cached, uploaded, or scheduled message executes after its original authentication and validation context is gone.",
      },
    ],
    auditQuestions: [
      "Which request and message parsing occurs before authentication, TLS termination, or application-pool isolation?",
      "Do proxies, HTTP.sys, server modules, queues, and applications agree on framing and canonicalization?",
      "Which paths, handlers, extensions, virtual directories, and queue properties select executable code?",
      "Are host, binding, certificate, queue, application pool, and caller identity authorized as one object?",
      "Can persisted messages or uploads be modified, rerouted, replayed, or executed after policy changes?",
      "Which management endpoints are reachable remotely and what authority do their individual methods expose?",
    ],
    labWorkflow: [
      "Build an isolated server with the exact affected roles and capture a normal request, upload, queue send/receive, and management change.",
      "Map each byte across proxy, kernel listener, worker, protocol module, queue store, handler, and application boundary.",
      "Test framing, encoding, path, host, certificate, queue, transaction, retry, and cancellation dimensions independently.",
      "Use separate identities and application pools to prove any cross-tenant or cross-authority impact.",
      "Compare server and client fixes plus configuration defaults before concluding whether a mitigation removes reachability.",
    ],
    relatedConcepts: [
      {
        label: "Path canonicalization",
        href: "/windows-security-concepts/path-canonicalization/",
      },
      {
        label: "Unsafe protocol parsing",
        href: "/windows-security-concepts/unsafe-protocol-parsing/",
      },
      {
        label: "Authorization bypass",
        href: "/windows-security-concepts/authorization-bypass/",
      },
    ],
  },
];

export const windowsServiceTopicBySlug = new Map(
  windowsServiceTopicContent.map((topic) => [topic.slug, topic]),
);

export const windowsServiceTopicByCategory = new Map(
  windowsServiceTopicContent.map((topic) => [topic.category, topic]),
);
