import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const overwriteGenerated = process.argv.includes("--overwrite-generated");
const blogDirectory = path.join(root, "src", "content", "blog");
const labSlugs = new Set([
  "backup-restore-privileges-lab",
  "reproducible-windows-malware-analysis-lab",
]);
const vulnerabilitySlugs = new Set([
  "authentication-coercion-petitpotam-relay-boundaries",
  "print-spooler-boundaries-and-printnightmare",
]);
const coverage = JSON.parse(
  await readFile(
    path.join(root, "src", "data", "yunolay-topic-coverage.json"),
    "utf8",
  ),
);

const sequences = {
  "windows-privesc": [
    "windows-privesc-trust-boundary-model",
    "access-tokens-sids-integrity-privileges",
    "windows-privesc-enumeration-evidence-workflow",
    "windows-event-logs-evidence-and-tamper-signals",
    "weak-service-dacls-and-binary-path-control",
    "unquoted-service-path-reachability",
    "alwaysinstallelevated-policy-boundary",
    "print-spooler-boundaries-and-printnightmare",
    "dll-search-order-privileged-sink",
    "com-activation-hijacking-boundaries-telemetry",
    "registry-autoruns-imagepath-permission-boundaries",
    "scheduled-tasks-startup-folders-privilege-boundaries",
    "wmi-lateral-movement-persistence-telemetry",
    "lolbins-trust-boundaries-and-telemetry",
    "token-impersonation-potato-family-boundaries",
    "named-pipe-impersonation-security-context",
    "uac-auto-elevation-boundary-model",
    "backup-restore-privileges-lab",
    "dpapi-credential-manager-protection-boundaries",
    "lsass-credential-material-ppl-credential-guard",
    "volume-shadow-copy-security-boundaries",
    "powershell-language-modes-logging-and-obfuscation",
    "amsi-defender-scanning-boundaries-hardening",
    "applocker-wdac-policy-design-gaps",
    "windows-firewall-wfp-policy-telemetry",
    "authentication-coercion-petitpotam-relay-boundaries",
    "wsl-security-boundaries-and-telemetry",
  ],
  "malware-c2": [
    "malware-c2-execution-tasking-telemetry-model",
    "reproducible-windows-malware-analysis-lab",
    "pe-static-triage-bounds-checked",
    "malicious-office-documents-static-dynamic-triage",
    "yara-rule-engineering-test-quality",
    "dynamic-malware-analysis-evidence-workflow",
    "packed-malware-unpacking-anti-debugging",
    "process-injection-state-transitions-detection",
    "windows-shellcode-position-independent-analysis",
    "shellcode-loader-memory-protection-telemetry",
    "beacon-object-files-coff-loader-analysis",
    "bits-jobs-transfer-persistence-telemetry",
    "com-activation-hijacking-boundaries-telemetry",
    "windows-persistence-run-keys-services-wmi",
    "linux-persistence-systemd-udev-pam-analysis",
    "lolbins-trust-boundaries-and-telemetry",
    "c2-transport-design-detection",
    "c2-framework-architecture-comparison",
    "malleable-c2-profiles-protocol-telemetry",
    "amsi-defender-scanning-boundaries-hardening",
  ],
  "windows-internals": [
    "windows-process-thread-token-handle-model",
    "eprocess-process-lifetime-address-space",
    "ethread-kthread-scheduler-context-switch",
    "peb-teb-loader-thread-state",
    "windows-thread-pools-worker-factories",
    "dispatcher-objects-synchronization-irql",
    "job-objects-silos-containers",
    "windows-loader-pe-imports-relocations-tls",
    "windows-boot-chain-uefi-winload-smss",
    "windows-virtual-memory-page-tables-vads-working-sets",
    "section-objects-mapped-files-copy-on-write",
    "windows-heaps-nt-heap-segment-heap",
    "windows-cache-manager-fast-io-coherency",
    "kernel-pool-allocators-tags-segment-heap",
    "object-manager-names-handles-security",
    "access-tokens-sids-integrity-privileges",
    "lsa-authentication-logon-sessions-credential-guard",
    "io-manager-irp-ioctl-buffering",
    "windows-driver-model-wdm-kmdf-driver-objects",
    "filter-manager-minifilter-altitudes-callbacks",
    "service-control-manager-services-svchost",
    "registry-hives-cells-configuration-manager",
    "alpc-ports-messages-impersonation",
    "wmi-internals-providers-repository-eventing",
    "system-calls-previousmode-wow64",
    "wow64-thunking-redirection-dual-ntdll",
    "etw-providers-sessions-consumers-internals",
    "seh-veh-unwind-dispatch",
    "kuser-shared-data-time-version-mitigations",
    "irql-interrupts-dpcs-apcs",
    "kernel-protections-patchguard-dse-hvci",
    "win32k-user-gdi-sessions-attack-surface",
  ],
};

const trackRanges = {
  "windows-privesc": [
    [2, "foundations"],
    [4, "discovery-evidence"],
    [8, "service-boundaries"],
    [14, "execution-persistence"],
    [17, "token-ipc"],
    [21, "credentials-recovery"],
    [25, "policy-controls"],
    [27, "lateral-boundaries"],
  ],
  "malware-c2": [
    [2, "foundations"],
    [5, "static-analysis"],
    [7, "dynamic-analysis"],
    [11, "memory-execution"],
    [16, "execution-persistence"],
    [19, "c2-operations"],
    [20, "detection-engineering"],
  ],
  "windows-internals": [
    [8, "processes-execution"],
    [9, "boot-architecture"],
    [14, "memory-manager"],
    [17, "security-objects"],
    [20, "io-drivers"],
    [24, "ipc-services"],
    [29, "telemetry-runtime"],
    [32, "kernel-platform"],
  ],
};

const existing = new Set([
  "windows-privesc-trust-boundary-model",
  "weak-service-dacls-and-binary-path-control",
  "dll-search-order-privileged-sink",
  "backup-restore-privileges-lab",
  "malware-c2-execution-tasking-telemetry-model",
  "reproducible-windows-malware-analysis-lab",
  "pe-static-triage-bounds-checked",
  "c2-transport-design-detection",
  "windows-process-thread-token-handle-model",
  "object-manager-names-handles-security",
  "system-calls-previousmode-wow64",
  "io-manager-irp-ioctl-buffering",
]);

const titleOverrides = {
  "access-tokens-sids-integrity-privileges":
    "Windows Access Tokens: SIDs, Integrity Levels, Privileges, and DACLs",
  "lolbins-trust-boundaries-and-telemetry":
    "LOLBins: Trust Boundaries, Reachability, and Telemetry",
  "amsi-defender-scanning-boundaries-hardening":
    "AMSI and Defender: Scanning Boundaries, Failure Modes, and Hardening",
  "com-activation-hijacking-boundaries-telemetry":
    "COM Activation and Hijacking: Resolution, Security Boundaries, and Telemetry",
  "lsass-credential-material-ppl-credential-guard":
    "LSASS Credential Material, LSA Protection, and Credential Guard",
  "token-impersonation-potato-family-boundaries":
    "Token Impersonation and the Potato Family: Boundaries, Preconditions, and Mitigations",
  "packed-malware-unpacking-anti-debugging":
    "Packed Malware and Anti-Debugging: Evidence-Led Unpacking",
  "c2-framework-architecture-comparison":
    "C2 Framework Architecture: Cobalt Strike, Sliver, and Mythic Compared",
  "windows-virtual-memory-page-tables-vads-working-sets":
    "Windows Virtual Memory: Page Tables, VADs, and Working Sets",
  "kernel-pool-allocators-tags-segment-heap":
    "Windows Kernel Pool: Allocators, Tags, and Failure Analysis",
};

const detailText = {
  "access-tokens-sids-integrity-privileges":
    "A token carries user and group SIDs, enabled and deny-only attributes, privileges, integrity information, virtualization state, and restriction data; object access combines the caller token, requested access, generic mapping, the object's security descriptor, mandatory policy, and any privilege-assisted path; a primary token supplies a process-wide default while an impersonation token can change a thread's effective security context; authorization evidence must record the exact token, object, access mask, and access-check result instead of reducing the outcome to an account name.",
  "windows-privesc-enumeration-evidence-workflow":
    "Enumeration is hypothesis generation, not proof of exploitation; automated findings must be reduced to actor control, a privileged consumer, a reachable trigger, and a measurable privileged sink; access checks should be performed as the actual standard-user token because administrator-shell results create false positives; a useful evidence bundle preserves command lines, timestamps, ACLs, service configuration, token state, and a negative control.",
  "windows-event-logs-evidence-and-tamper-signals":
    "Windows channels have separate providers, manifests, retention policies, access descriptors, and rollover behavior; an event identifier is meaningful only with provider name, version, channel, and rendered fields; missing events can result from disabled providers, collection gaps, rollover, filtering, or tampering and therefore are not proof of absence; resilient investigations correlate Security, System, PowerShell, Defender, WMI, Task Scheduler, Sysmon, and external collection records.",
  "print-spooler-boundaries-and-printnightmare":
    "The spooler is a privileged service that brokers client RPC, driver installation, rendering, and print-provider behavior; PrintNightmare covered related but distinct remote-code-execution and local-privilege-escalation paths whose exposure depended on patch and policy state; Point and Print policy, driver-signing requirements, service availability, and remote reachability change the effective boundary; safe assessment proves configuration and version state without installing a driver or sending an exploit payload.",
  "named-pipe-impersonation-security-context":
    "A named-pipe server may impersonate a connected client only after a valid communication boundary and with an allowed impersonation level; impersonation changes the current thread's effective token rather than silently replacing the process primary token; SeImpersonatePrivilege, token type, session, integrity, and target-token restrictions determine what can happen next; correct analysis pairs pipe ACLs and server identity with the origin of the privileged client connection.",
  "wmi-lateral-movement-persistence-telemetry":
    "WMI combines CIM schema, providers, the repository, RPC or DCOM transport, namespaces, and per-namespace security; remote method invocation and permanent event subscriptions are different mechanisms with different artifacts; FilterToConsumerBinding joins an event filter to a consumer and should be examined together with CreatorSID and namespace ACLs; telemetry spans WMI-Activity logs, process ancestry, RPC/network evidence, repository state, and the privileged identity hosting a provider.",
  "powershell-language-modes-logging-and-obfuscation":
    "Execution policy is an administrative safety feature rather than a security boundary; language mode, application control, AMSI, script-block logging, module logging, transcription, and process policy form separate controls; obfuscation alters lexical representation but cannot remove the semantic operations a script requests; analysis should preserve the original bytes, normalized syntax, decoded constants, invocation context, engine version, and downstream behavior.",
  "amsi-defender-scanning-boundaries-hardening":
    "AMSI is an interface through which participating applications submit content and metadata to an antimalware provider; coverage depends on the host integrating AMSI, the content reaching a scan point, provider health, and policy state; Defender real-time protection, behavior monitoring, cloud protection, attack-surface-reduction rules, and tamper protection are related but distinct layers; validation should use benign test content and provider-health telemetry rather than bypass code.",
  "registry-autoruns-imagepath-permission-boundaries":
    "An autorun location matters only when a more privileged consumer reads it and the lower-privileged actor can change the effective command or a dependency; registry-key permissions, value permissions inherited through the key, filesystem ACLs, environment expansion, quoting, and command parsing all contribute; service ImagePath is controlled through SCM operations and registry representation should not be treated as an ordinary autorun value; defenders should capture the old and new value, writer identity, consumer context, and trigger.",
  "scheduled-tasks-startup-folders-privilege-boundaries":
    "A task definition separates principal, trigger, action, settings, and stored credentials or service-account context; writable XML or an action binary is not enough unless Task Scheduler consumes the changed material under a stronger context; folder and task security descriptors govern management operations while referenced file ACLs govern action replacement; analysis should distinguish per-user startup locations from all-users startup and privileged scheduled tasks.",
  "dpapi-credential-manager-protection-boundaries":
    "DPAPI derives protection from a user's or machine's master-key hierarchy rather than providing universal secrecy independent of logon context; Credential Manager stores typed credentials and metadata whose availability depends on caller identity, logon state, policy, and protection mechanism; domain backup keys, roaming, password changes, and machine-scoped blobs alter recovery paths; a safe lab uses self-created test secrets and records blob scope, owner SID, master-key identifiers, and decryption context.",
  "lsass-credential-material-ppl-credential-guard":
    "LSASS hosts authentication packages, creates logon sessions, and brokers policy and credential operations, but not every logon type leaves the same material; RunAsPPL raises the bar for opening or injecting into LSASS by requiring protected-process-compatible signers; Credential Guard isolates selected secrets in VTL1 behind an LSA isolation boundary while LSASS remains in VTL0; effective protection depends on hardware, virtualization-based security, policy, boot trust, and compatibility state.",
  "uac-auto-elevation-boundary-model":
    "UAC splits an administrator's interactive logon into linked token contexts and mediates elevation consent; auto-elevation is granted only to eligible signed components and is influenced by manifest, policy, integrity, and invocation path; the secure desktop and consent behavior vary with UAC policy and account type; UAC is not a boundary against an already-compromised administrator, but it remains a meaningful control against silent elevation and accidental privilege use.",
  "alwaysinstallelevated-policy-boundary":
    "AlwaysInstallElevated becomes dangerous only when both the machine and current-user policy values enable elevated Windows Installer transactions; Windows Installer still parses package metadata, custom actions, repair, and rollback through a complex service boundary; finding one registry value is an incomplete result and should be reported as a configuration precondition rather than confirmed escalation; mitigation requires disabling both policy values and auditing software-deployment assumptions.",
  "unquoted-service-path-reachability":
    "An unquoted service ImagePath containing spaces can be split into candidate executable paths by Windows command-line resolution; exploitability additionally requires that a standard user can create the earliest reachable candidate and that the service can be restarted or will start later; arguments, environment expansion, existing directories, service account, and filesystem inheritance determine the real path; validation should enumerate candidates and ACLs without planting an executable.",
  "token-impersonation-potato-family-boundaries":
    "Potato-family techniques are families of coercion and token-impersonation chains rather than one universal exploit; they require a privileged authentication or activation path, an attacker-controlled endpoint, a usable impersonation level, and token privileges such as SeImpersonatePrivilege; Windows version, service hardening, COM/RPC behavior, authentication protections, session isolation, and patches invalidate many variants; analysis should name the exact primitive and preconditions instead of reporting only a tool name.",
  "authentication-coercion-petitpotam-relay-boundaries":
    "Authentication coercion causes a machine or service identity to authenticate to a chosen endpoint but does not by itself grant privilege; relay requires a compatible inbound protocol, absent or insufficient channel binding or signing, and a target that accepts the relayed identity for a useful operation; AD CS web enrollment historically created a high-impact target when template and endpoint conditions aligned; safe assessment inventories exposure and policy without coercing production identities.",
  "wsl-security-boundaries-and-telemetry":
    "WSL 1 and WSL 2 have different architecture, kernel, filesystem, and network boundaries; Windows-to-Linux and Linux-to-Windows interoperability exposes path translation, process launching, environment transfer, and mounted-drive policy; distribution registration and per-user virtual disks create artifacts outside the usual Windows process narrative; monitoring must correlate wsl.exe and wslhost activity, utility VM or Pico process context, network flows, mounted files, and Windows-side consumers.",
  "applocker-wdac-policy-design-gaps":
    "AppLocker is a rule-based application-control technology while WDAC applies code-integrity policy at a stronger platform boundary; publisher, path, hash, packaged-app, script, DLL, driver, and managed-installer decisions have different trust implications; audit mode and enforcement mode must be distinguished in evidence; a policy review searches for writable trusted paths, overly broad publisher ranges, unmanaged interpreters, missing script or DLL coverage, and deployment paths that cannot sustain enforcement.",
  "windows-firewall-wfp-policy-telemetry":
    "Windows Firewall is implemented through Windows Filtering Platform layers, filters, callouts, providers, sublayers, and policy stores; local rules can be merged with domain policy depending on profile and management settings; changing a visible firewall rule is different from registering a WFP filter or disabling a provider; defenders should preserve effective policy, active profile, rule origin, filter identifiers, service health, and network events before attributing a gap to tampering.",
  "com-activation-hijacking-boundaries-telemetry":
    "COM activation resolves a class identifier through registration, activation context, bitness, and server type before a client receives an interface pointer; per-user registration can shadow machine-wide registration in some activation paths but not every CLSID or packaged scenario; in-process servers inherit the client's token while local servers have their own launch and access security; a complete finding proves a real client, resolution precedence, writable registration, trigger, and resulting execution context.",
  "volume-shadow-copy-security-boundaries":
    "VSS coordinates requesters, writers, providers, snapshots, and exposed shadow-copy devices; the ability to enumerate a snapshot differs from the ability to create, expose, or read protected content inside it; backup privileges, filesystem ACLs, service configuration, storage limits, and writer state affect results; defensible recovery workflows use purpose-built test volumes and record snapshot identifiers, requester identity, writer status, access masks, and cleanup.",
  "lolbins-trust-boundaries-and-telemetry":
    "A living-off-the-land binary is a legitimate signed utility whose flexible behavior can cross a security boundary when supplied attacker-controlled input; a catalog entry is a hypothesis, not evidence that every argument works on every build; application control, network policy, child-process rules, user writable paths, and parent context determine reachability; detection should model unusual data flow and execution chains rather than blocking filenames without context.",
  "malicious-office-documents-static-dynamic-triage":
    "Modern Office files are ZIP-based Open XML packages while legacy compound files use OLE structured storage; macros, relationships, embedded objects, templates, DDE-like links, and XLM sheets expose different execution and evidence paths; VBA stomping creates disagreement between source streams and compiled p-code and must be handled as an integrity signal; analysis should start with structure and metadata, then use protected detonation only when static evidence cannot answer the question.",
  "c2-framework-architecture-comparison":
    "Cobalt Strike, Sliver, and Mythic separate operator interface, team server, payload or agent, transport profiles, tasking, and result storage in different ways; feature names are not directly comparable unless identity, protocol, execution, extension, and multi-tenant boundaries are aligned; open-source availability changes reviewability but not the need to validate deployed configuration; defenders gain more from invariant task and telemetry models than from product-name signatures.",
  "yara-rule-engineering-test-quality":
    "A YARA rule combines strings, modules, metadata, and a condition over bytes or parsed attributes; high-quality rules select stable family behavior while excluding compiler boilerplate and common library material; nocase, wide, fullword, regex, xor, base64, and private strings change both cost and match semantics; tests need representative positives, hard negatives, near misses, packed variants, performance limits, and a documented retirement policy.",
  "process-injection-state-transitions-detection":
    "Process injection is a set of memory, handle, thread, section, APC, and loader state transitions rather than a single API sequence; classic remote-thread injection, section mapping, process hollowing, reflective loading, and thread-context manipulation leave different artifacts; access rights and target architecture constrain each chain; detection should combine cross-process handle activity, executable-memory provenance, image and thread start relationships, and target-process expectations.",
  "windows-shellcode-position-independent-analysis":
    "Position-independent code cannot assume a fixed image base and therefore resolves data, APIs, or imports through relative addressing or runtime discovery; x64 stack alignment, shadow space, register volatility, exception metadata, and calling convention still apply; analysis separates decoder, resolver, configuration, transport, and final capability stages; safe exercises use shellcode-shaped byte arrays that return a constant and never resolve networking, process creation, or persistence APIs.",
  "packed-malware-unpacking-anti-debugging":
    "A packer transforms an original image into a loader stub plus compressed or encrypted material; the most useful transition is often when reconstructed code and imports become executable, not when a debugger reaches an arbitrary entry point; anti-debug checks may inspect timing, process state, exceptions, hardware breakpoints, environment artifacts, or API behavior; evidence-led unpacking records memory protections, writes, control transfers, module resolution, and dumped-image limitations.",
  "dynamic-malware-analysis-evidence-workflow":
    "Dynamic analysis is a controlled experiment with hypotheses, sensors, time bounds, and reset conditions; process, file, registry, service, task, WMI, network, and memory evidence must share a synchronized timeline; absence from one sensor is not a negative result until sensor coverage and health are tested; detonation should use approved samples, simulated services, controlled DNS, no production credentials, and a documented containment and disposal procedure.",
  "bits-jobs-transfer-persistence-telemetry":
    "BITS persists transfer jobs through a service-managed queue and can continue work across user sessions and network changes; a job has owner, type, state, files, notification behavior, retry timing, and credentials or proxy context; asynchronous execution makes process-only narratives incomplete; defenders correlate BITS client operational events, job enumeration, qmgr storage artifacts, destination paths, notification commands, network destinations, and the creating principal.",
  "linux-persistence-systemd-udev-pam-analysis":
    "systemd units and timers, udev rules, and PAM modules occupy different boot, device, and authentication trust boundaries; unit precedence and drop-in directories determine which definition wins; udev rules run in a constrained service context and should not be treated as an ordinary interactive shell; PAM changes can affect every authentication path, so analysis must preserve package ownership, module order, file hashes, journal evidence, and recovery access.",
  "shellcode-loader-memory-protection-telemetry":
    "A loader controls allocation, content placement, relocation or resolution, memory protection, execution transfer, and cleanup; executable private memory is a useful signal but legitimate runtimes also create it; staged decryption and indirect execution shift the order of observable transitions without removing them; safe analysis uses inert buffers and measures VirtualAlloc or section state, protection changes, thread starts, call stacks, and image provenance.",
  "malleable-c2-profiles-protocol-telemetry":
    "A malleable profile changes how identity, metadata, tasking, and results are encoded into protocol fields, timing, and endpoints; superficial resemblance to normal HTTP does not reproduce the surrounding client implementation, TLS fingerprint, DNS history, cache behavior, or user workflow; protocol invariants include message direction, retry, correlation identifiers, size distributions, and server state; detections should combine those invariants with host-side task and execution evidence.",
  "windows-persistence-run-keys-services-wmi":
    "Run keys, startup folders, services, scheduled tasks, WMI subscriptions, COM registration, and browser or Office extensibility invoke different privileged consumers; persistence is only established when the trigger recurs under the intended identity and survives the expected lifecycle event; per-user and per-machine locations have different permission and visibility models; an audit records writer, storage location, trigger, consumer, resulting context, telemetry, and removal procedure.",
  "beacon-object-files-coff-loader-analysis":
    "A Beacon Object File is a COFF object whose functions and relocations are resolved by an in-memory host rather than the normal PE loader; symbol resolution, relocation types, section permissions, argument packing, and host-provided APIs define the execution contract; malformed objects can corrupt the hosting process, which matters for both analysis and operator safety; defenders can inspect unusual COFF parsing, private executable mappings, call stacks, and network-task correlation.",
  "windows-virtual-memory-page-tables-vads-working-sets":
    "A process address space is described through regions and VADs while hardware page tables translate individual virtual pages; valid, transition, prototype, demand-zero, pagefile-backed, and copy-on-write states describe different ownership and residency conditions; the working set is the resident subset currently charged to a process, not its entire committed address space; investigations should correlate VAD metadata, PTE state, section backing, protection, commit, and page provenance.",
  "service-control-manager-services-svchost":
    "The Service Control Manager maintains a service database, creates service processes, sends control requests, and enforces service-object access; ImagePath, ServiceDll, account, start mode, dependencies, failure actions, triggers, and required privileges affect lifecycle; svchost groups multiple service DLLs according to configuration and modern builds may split services for isolation; analysis separates SCM metadata, registry representation, process token, service SID, pipe or RPC interfaces, and binary ACLs.",
  "etw-providers-sessions-consumers-internals":
    "An ETW provider defines events and writes them when enabled by a tracing session; controllers configure sessions, keywords, levels, buffering, and destinations while consumers decode the resulting records; manifest, TraceLogging, MOF, and WPP providers carry metadata differently; reliable collection records provider GUID, event descriptor, session settings, lost-event counters, clock source, stack-walk policy, and decoder version.",
  "registry-hives-cells-configuration-manager":
    "The Configuration Manager maps registry hives into kernel-managed structures and persists keys, values, security cells, and transaction metadata; logical key paths are views over hive and namespace behavior rather than ordinary filesystem directories; WOW64 redirection, virtualization, symbolic links, volatile keys, and per-user hive loading alter what a process observes; forensic interpretation should preserve hive generation, transaction logs, last-write times, security descriptors, and live-versus-offline context.",
  "windows-driver-model-wdm-kmdf-driver-objects":
    "Driver objects contain dispatch entry points and reference device objects while device stacks connect bus, function, and filter roles; WDM exposes IRP lifecycle directly, whereas KMDF wraps state, queues, callbacks, object parenting, and synchronization policy; Plug and Play and power transitions create state beyond create/read/write/device-control dispatch; review should map device interfaces, symbolic links, ACLs, IOCTL access bits, buffering mode, queues, cancellation, and teardown ownership.",
  "windows-loader-pe-imports-relocations-tls":
    "The user-mode loader maps an image, validates headers, creates sections, applies relocations, resolves imports, processes activation contexts and TLS, and calls initialization routines under loader constraints; KnownDLLs, side-by-side assemblies, API sets, packaged-app rules, and explicit LoadLibraryEx flags alter resolution; delay imports and forwarded exports add indirection; analysis distinguishes file layout, mapped-image layout, loader lists, reference counts, search policy, and initialization order.",
  "irql-interrupts-dpcs-apcs":
    "Interrupt request levels prioritize interrupt and synchronization work but are not thread privilege levels; an ISR performs minimal device-specific work and usually schedules a DPC for deferred processing; APCs execute in a thread context and have kernel, special-kernel, and user-mode delivery rules; correctness depends on IRQL, pageable-code restrictions, lock ordering, CPU locality, interrupt affinity, and object lifetime across deferred callbacks.",
  "seh-veh-unwind-dispatch":
    "Windows exception dispatch separates hardware or software fault creation, first-chance notification, vectored handlers, language-specific handlers, stack unwinding, and second-chance termination; x64 uses table-based unwind metadata rather than the classic x86 linked registration chain; continuation is valid only for continuable exceptions and correct context; analysis records exception code, parameters, fault address, module mapping, unwind metadata, handler order, and debugger influence.",
  "alpc-ports-messages-impersonation":
    "ALPC provides connection ports, communication ports, messages, attributes, shared sections, and handle transfer for local IPC; a server's namespace and security descriptor control connection while per-message attributes control views, handles, and security context; impersonation must be tied to a specific client message and allowed level; an attack-surface map includes port discovery, broker identity, message schema, length validation, transferred objects, callbacks, cancellation, and disconnect lifetime.",
  "wow64-thunking-redirection-dual-ntdll":
    "WoW64 combines a 32-bit user-mode environment with translation and a native 64-bit kernel; a 32-bit process has architecture-specific ntdll behavior and transitions through WoW64 support before native system service dispatch; filesystem and registry redirection preserve compatibility but can be disabled or bypassed in defined cases; analysis must label pointer width, structure layout, module view, system directory, registry view, and debugger architecture.",
  "kernel-pool-allocators-tags-segment-heap":
    "Kernel pool supplies paged and nonpaged allocations through evolving allocator internals that differ across Windows builds; pool tags are accounting hints rather than trustworthy object types; quota, NUMA locality, cache behavior, executable policy, and special-pool instrumentation affect allocation; corruption analysis starts from the first invalid write or lifetime transition and uses tags, headers, verifier, stack traces, object ownership, and version-matched symbols as evidence.",
  "windows-boot-chain-uefi-winload-smss":
    "The boot chain moves from firmware and Secure Boot policy through Windows Boot Manager, winload, kernel initialization, Session Manager, Wininit, services, and interactive logon; BCD selects loader behavior but not every setting is honored under Secure Boot or measured-boot policy; ELAM, code integrity, VBS, and hypervisor startup establish security properties before ordinary services; debugging should identify the phase, component, trust input, persistent configuration, and earliest observable failure.",
  "eprocess-process-lifetime-address-space":
    "EPROCESS is a version-specific executive process object that references address-space, token, handle-table, job, security, and scheduling state rather than defining a stable public ABI; creation and teardown proceed through multiple callbacks and reference-counted lifetimes; process identifiers and active-process lists are indexes, not ownership guarantees; debugging must use matching symbols and distinguish live process object, exiting process, retained handle, and reused identifier.",
  "ethread-kthread-scheduler-context-switch":
    "ETHREAD layers executive thread state around the scheduler-oriented KTHREAD; readiness, standby, running, waiting, transition, and termination states interact with priority, quantum, affinity, ideal processor, and heterogeneous scheduling policy; a context switch saves architectural state but does not itself imply a security-context change; thread investigation correlates wait reason, wait blocks, locks, IRQL, APC state, stack, owning process, token impersonation, and build-specific fields.",
  "windows-heaps-nt-heap-segment-heap":
    "Windows exposes process heap APIs over implementations that include the traditional NT heap and the Segment Heap; frontend and backend allocators, size classes, metadata, delayed free, LFH behavior, guard instrumentation, and corruption checks vary by mode and build; a heap handle does not identify ownership of every pointer without allocation evidence; triage should use page heap or verifier where possible and separate use-after-free, overflow, double free, and metadata symptom.",
  "kernel-protections-patchguard-dse-hvci":
    "Driver Signature Enforcement controls which kernel images may load, HVCI moves selected code-integrity decisions into a virtualization-protected trust level, and PatchGuard detects unsupported modification of critical kernel state; these controls have different activation, hardware, policy, and compatibility requirements; a single registry value does not prove effective enforcement; validation combines System Information, code-integrity logs, Device Guard state, boot configuration, loaded drivers, and supported Microsoft diagnostics.",
  "windows-cache-manager-fast-io-coherency":
    "The Cache Manager provides shared file caching through mapped views and cooperates with the Memory Manager and file systems; VACBs map portions of cached files while shared cache maps track state across file objects; cached I/O, paging I/O, memory mapping, write-behind, lazy writing, and read-ahead must remain coherent; Fast I/O is an optional dispatch path that can decline and fall back to IRPs, not a universal replacement for the I/O Manager.",
  "filter-manager-minifilter-altitudes-callbacks":
    "Filter Manager orders minifilters by altitude and instances within file-system stacks; pre-operation and post-operation callbacks can observe or modify selected operations while contexts attach state to volumes, instances, files, streams, handles, or transactions; callback IRQL, reentrancy, name queries, cancellation, and teardown create subtle lifetime rules; security review maps registrations, altitude, communication ports, message schema, bypass paths, and generated I/O.",
  "section-objects-mapped-files-copy-on-write":
    "A section object represents shared backing that can be mapped into one or more processes or system space; image, data-file, pagefile-backed, shared, and copy-on-write mappings have different prototype-PTE and commit behavior; a mapped view's protection is constrained by section creation and requested view access; analysis connects section handles, control areas, file objects, VADs, per-page state, dirtying, inheritance, and image-loader semantics.",
  "wmi-internals-providers-repository-eventing":
    "WMI exposes CIM classes through providers hosted in processes such as WmiPrvSE and stores selected schema or instance data in a repository; a namespace defines security and provider registration scope; intrinsic events poll repository-visible changes while extrinsic events originate with providers; troubleshooting should separate client query, CIMOM routing, provider execution, repository state, permanent subscription objects, host quota, and ETW or operational logs.",
  "lsa-authentication-logon-sessions-credential-guard":
    "LSA policy, authentication packages, credential providers, Winlogon, LSASS, SAM or Active Directory, and Security Support Providers have separate roles; a successful authentication creates a logon session and token through a specific logon type and package; cached interactive logon, network authentication, delegation, and service logon retain different material; Credential Guard and LSA protection change storage and process access but do not remove every credential or delegation risk.",
  "job-objects-silos-containers":
    "A job object groups processes for accounting, limits, notifications, CPU and memory policy, and coordinated termination; nested jobs changed historical assignment constraints and effective limits compose across the hierarchy; server silos extend isolation for container-like environments by virtualizing selected namespaces and system views; analysis distinguishes job membership, breakaway policy, completion-port messages, resource limits, root-directory or object-namespace effects, and host boundary.",
  "peb-teb-loader-thread-state":
    "The PEB contains user-mode process environment and loader-related state while each TEB contains per-thread state such as stack bounds, TLS, last-error information, and exception-related fields; both structures are implementation details that vary by architecture and build; kernel security decisions must not trust writable user-mode copies; debugging should use symbols and APIs, label native versus WoW64 views, and avoid assuming undocumented offsets.",
  "windows-thread-pools-worker-factories":
    "The Windows thread-pool API schedules work, timers, waits, and asynchronous I/O over managed worker threads; cleanup groups and callback environments define cancellation, priority, affinity, and teardown relationships; worker factories participate in lower-level process worker management but are not equivalent to every public thread-pool abstraction; lifetime analysis follows submission, pending state, callback start, cancellation race, callback return, object close, and module unload.",
  "dispatcher-objects-synchronization-irql":
    "Dispatcher objects such as events, mutexes, semaphores, timers, threads, and processes expose signaled state and wait semantics; spin locks and push locks solve different IRQL and scheduling problems and must not be mixed casually; alertable waits permit APC delivery while wait-any and wait-all have different satisfaction rules; deadlock analysis records lock order, ownership, recursion, wait blocks, IRQL, APC disablement, timeouts, and object lifetime.",
  "kuser-shared-data-time-version-mitigations":
    "KUSER_SHARED_DATA is a kernel-maintained page mapped read-only into user space at a well-known address for time, version, system-root, and selected mitigation or feature data; fields and semantics evolve and should be interpreted with version-matched symbols or headers; fast user-mode reads avoid a system call but require consistency protocols for multiword updates; security review treats the page as observable metadata, not an authorization source.",
  "win32k-user-gdi-sessions-attack-surface":
    "The GUI subsystem spans user-mode libraries, CSRSS-related responsibilities, session state, desktop and window-station objects, and win32k kernel components for USER and GDI operations; handles in USER and GDI tables are not ordinary Object Manager handles; message dispatch, callbacks, composition, fonts, graphics drivers, and shared data create complex cross-boundary flows; modern mitigations, process win32k lockdown, session isolation, and build changes alter reachability.",
};

const inspectionProbes = {
  "access-tokens-sids-integrity-privileges": String.raw`whoami /all
whoami /groups
whoami /priv`,
  "windows-privesc-enumeration-evidence-workflow": String.raw`Get-CimInstance Win32_Service |
  Select-Object Name, StartName, State, PathName
Get-ScheduledTask | Select-Object TaskPath, TaskName, State`,
  "windows-event-logs-evidence-and-tamper-signals": String.raw`wevtutil enum-logs
wevtutil get-log Security
Get-WinEvent -ListLog * | Select-Object LogName, IsEnabled, RecordCount`,
  "print-spooler-boundaries-and-printnightmare": String.raw`Get-Service Spooler
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ErrorAction SilentlyContinue
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10`,
  "named-pipe-impersonation-security-context": String.raw`Get-ChildItem \\.\pipe\ | Sort-Object Name
whoami /priv
# Use Process Explorer or WinObj to inspect only a lab pipe's owner and ACL.`,
  "wmi-lateral-movement-persistence-telemetry": String.raw`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer
Get-WinEvent -LogName Microsoft-Windows-WMI-Activity/Operational -MaxEvents 20`,
  "powershell-language-modes-logging-and-obfuscation": String.raw`$ExecutionContext.SessionState.LanguageMode
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 20`,
  "amsi-defender-scanning-boundaries-hardening": String.raw`Get-MpComputerStatus |
  Select-Object AMServiceEnabled, AntivirusEnabled, BehaviorMonitorEnabled, RealTimeProtectionEnabled
Get-MpPreference | Select-Object DisableScriptScanning, DisableRealtimeMonitoring`,
  "registry-autoruns-imagepath-permission-boundaries": String.raw`Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-CimInstance Win32_Service | Select-Object Name, StartName, PathName`,
  "scheduled-tasks-startup-folders-privilege-boundaries": String.raw`Get-ScheduledTask | Select-Object TaskPath, TaskName, State
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"`,
  "dpapi-credential-manager-protection-boundaries": String.raw`whoami /user
Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Force -ErrorAction SilentlyContinue
cmdkey /list`,
  "lsass-credential-material-ppl-credential-guard": String.raw`Get-CimInstance Win32_DeviceGuard |
  Select-Object SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus
Get-WinEvent -LogName Microsoft-Windows-CodeIntegrity/Operational -MaxEvents 20`,
  "uac-auto-elevation-boundary-model": String.raw`whoami /groups
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop`,
  "alwaysinstallelevated-policy-boundary": String.raw`Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue`,
  "unquoted-service-path-reachability": String.raw`Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -match " " -and $_.PathName -notmatch '^\s*"' } |
  Select-Object Name, StartName, State, PathName
# Inspect candidate parents with: icacls.exe "C:\Path"`,
  "token-impersonation-potato-family-boundaries": String.raw`whoami /priv
whoami /groups
Get-ComputerInfo | Select-Object WindowsVersion, OsBuildNumber`,
  "authentication-coercion-petitpotam-relay-boundaries": String.raw`Get-SmbServerConfiguration |
  Select-Object EnableSecuritySignature, RequireSecuritySignature
Get-WindowsFeature ADCS-Web-Enrollment -ErrorAction SilentlyContinue
# Inventory only; do not coerce an account or relay authentication.`,
  "wsl-security-boundaries-and-telemetry": String.raw`wsl.exe --status
wsl.exe --list --verbose
Get-WinEvent -ListLog *WSL* -ErrorAction SilentlyContinue`,
  "applocker-wdac-policy-design-gaps": String.raw`Get-AppLockerPolicy -Effective -Xml
Get-CimInstance -ClassName Win32_DeviceGuard |
  Select-Object CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus
Get-WinEvent -LogName Microsoft-Windows-CodeIntegrity/Operational -MaxEvents 20`,
  "windows-firewall-wfp-policy-telemetry": String.raw`Get-NetFirewallProfile |
  Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
Get-NetFirewallRule | Group-Object PolicyStoreSourceType
netsh.exe wfp show state`,
  "com-activation-hijacking-boundaries-telemetry": String.raw`$clsid = "{00000000-0000-0000-0000-000000000000}" # replace with a lab CLSID
Get-Item "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid" -ErrorAction SilentlyContinue
Get-Item "HKCU:\Software\Classes\CLSID\$clsid" -ErrorAction SilentlyContinue`,
  "volume-shadow-copy-security-boundaries": String.raw`Get-CimInstance Win32_ShadowCopy |
  Select-Object ID, InstallDate, DeviceObject, VolumeName
vssadmin.exe list writers
whoami /priv`,
  "lolbins-trust-boundaries-and-telemetry": String.raw`Get-AuthenticodeSignature "$env:SystemRoot\System32\certutil.exe"
Get-Item "$env:SystemRoot\System32\certutil.exe" |
  Select-Object FullName, Length, VersionInfo
# Compare observed behavior with the exact binary hash and OS build.`,
  "malicious-office-documents-static-dynamic-triage": String.raw`Get-FileHash -Algorithm SHA256 .\fixture.docm
Expand-Archive .\fixture.docm .\expanded-doc -Force
Get-ChildItem .\expanded-doc -Recurse | Select-Object FullName, Length`,
  "c2-framework-architecture-comparison": String.raw`# Offline architecture comparison record
@{
  Identity = "agent and operator authentication"
  Tasking = "queue, acknowledgement, retry, result correlation"
  Extension = "plugin, BOF, module, or task boundary"
  Storage = "server-side evidence and retention"
} | ConvertTo-Json`,
  "yara-rule-engineering-test-quality": String.raw`yara.exe -w -s .\rules\candidate.yar .\fixtures\positive
yara.exe -w -s .\rules\candidate.yar .\fixtures\hard-negative
yara.exe --print-stats .\rules\candidate.yar .\fixtures\corpus`,
  "process-injection-state-transitions-detection": String.raw`Get-WinEvent -FilterHashtable @{
  LogName = "Microsoft-Windows-Sysmon/Operational"
  Id = 8, 10
} -MaxEvents 50
# Correlate handle access, memory provenance, and thread start; do not inject.`,
  "windows-shellcode-position-independent-analysis": String.raw`# Analyze inert bytes without executing them
Format-Hex .\fixtures\return-constant.bin
Get-FileHash -Algorithm SHA256 .\fixtures\return-constant.bin
dumpbin.exe /disasm .\fixtures\owned-object.obj`,
  "packed-malware-unpacking-anti-debugging": String.raw`Get-FileHash -Algorithm SHA256 .\fixture.exe
Get-AuthenticodeSignature .\fixture.exe
dumpbin.exe /headers .\fixture.exe
# Compare file-backed sections with memory only inside the isolated lab.`,
  "dynamic-malware-analysis-evidence-workflow": String.raw`Get-Date -Format o
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 50
Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess`,
  "bits-jobs-transfer-persistence-telemetry": String.raw`Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
  Select-Object DisplayName, OwnerAccount, JobState, TransferType
Get-WinEvent -LogName Microsoft-Windows-Bits-Client/Operational -MaxEvents 30`,
  "linux-persistence-systemd-udev-pam-analysis": String.raw`systemctl list-unit-files --state=enabled
systemctl list-timers --all
find /etc/udev/rules.d /etc/pam.d -maxdepth 2 -type f -printf '%p %TY-%Tm-%Td %TH:%TM\n'`,
  "shellcode-loader-memory-protection-telemetry": String.raw`Get-WinEvent -FilterHashtable @{
  LogName = "Microsoft-Windows-Sysmon/Operational"
  Id = 1, 7, 8, 10
} -MaxEvents 50
# Use an inert buffer and observe allocation/protection transitions only.`,
  "malleable-c2-profiles-protocol-telemetry": String.raw`# Summarize a saved, authorized packet capture
tshark -r .\fixtures\owned-traffic.pcapng -q -z io,stat,10
tshark -r .\fixtures\owned-traffic.pcapng -Y http.request -T fields -e frame.time_epoch -e http.host -e http.request.uri`,
  "windows-persistence-run-keys-services-wmi": String.raw`Get-CimInstance Win32_StartupCommand
Get-CimInstance Win32_Service | Select-Object Name, StartMode, StartName, PathName
Get-ScheduledTask | Select-Object TaskPath, TaskName, State`,
  "beacon-object-files-coff-loader-analysis": String.raw`dumpbin.exe /headers .\fixtures\owned-object.obj
dumpbin.exe /symbols .\fixtures\owned-object.obj
llvm-readobj.exe --sections --symbols --relocations .\fixtures\owned-object.obj`,
  "windows-virtual-memory-page-tables-vads-working-sets": String.raw`!process 0 1
!vad <EPROCESS>
!pte <virtual-address>
!working-set <process-address>`,
  "service-control-manager-services-svchost": String.raw`sc.exe query type= service state= all
tasklist.exe /svc
Get-CimInstance Win32_Service | Select-Object Name, StartName, ProcessId, PathName`,
  "etw-providers-sessions-consumers-internals": String.raw`logman.exe query -ets
logman.exe query providers
Get-WinEvent -ListProvider * | Select-Object Name, Id`,
  "registry-hives-cells-configuration-manager": String.raw`reg.exe query HKLM\SYSTEM\CurrentControlSet\Control
Get-ChildItem Registry::HKEY_USERS
# Offline hive work should use a copy plus its transaction logs.`,
  "windows-driver-model-wdm-kmdf-driver-objects": String.raw`lm t n
!drvobj <driver-name> 7
!devstack <device-object>
!wdfkd.wdfldr`,
  "windows-loader-pe-imports-relocations-tls": String.raw`!peb
lm
!dh <module-base> -f
gflags.exe /i owned-fixture.exe +sls`,
  "irql-interrupts-dpcs-apcs": String.raw`!irql
!dpcs
!interrupts
!thread <thread-address>`,
  "seh-veh-unwind-dispatch": String.raw`!analyze -v
.exr -1
.cxr
knL`,
  "alpc-ports-messages-impersonation": String.raw`!alpc /lpp
!handle 0 3 <process-address>
!token
# Inspect a lab server's port and message attributes read-only.`,
  "wow64-thunking-redirection-dual-ntdll": String.raw`.effmach
!wow64exts.info
lm m ntdll
!peb`,
  "kernel-pool-allocators-tags-segment-heap": String.raw`!poolused 2
!poolfind <pool-tag>
!verifier 3
!pool <allocation-address>`,
  "windows-boot-chain-uefi-winload-smss": String.raw`bcdedit.exe /enum all
Confirm-SecureBootUEFI
Get-CimInstance Win32_DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning`,
  "eprocess-process-lifetime-address-space": String.raw`!process 0 1
dt nt!_EPROCESS <process-address>
!handle 0 3 <process-address>
!token`,
  "ethread-kthread-scheduler-context-switch": String.raw`!thread <thread-address>
dt nt!_ETHREAD <thread-address>
!ready
!running -ti`,
  "windows-heaps-nt-heap-segment-heap": String.raw`!heap -s
!heap -stat -h <heap-address>
!heap -p -a <allocation-address>
gflags.exe /p /query owned-fixture.exe`,
  "kernel-protections-patchguard-dse-hvci": String.raw`Get-CimInstance Win32_DeviceGuard
Get-WinEvent -LogName Microsoft-Windows-CodeIntegrity/Operational -MaxEvents 30
msinfo32.exe`,
  "windows-cache-manager-fast-io-coherency": String.raw`!filecache
!vacb
!fileobj <file-object>
!ca <shared-cache-map>`,
  "filter-manager-minifilter-altitudes-callbacks": String.raw`fltmc.exe filters
fltmc.exe instances
!fltkd.filters
!fltkd.instances`,
  "section-objects-mapped-files-copy-on-write": String.raw`!handle 0 3
!vad <process-address>
!ca <control-area>
!pte <mapped-address>`,
  "wmi-internals-providers-repository-eventing": String.raw`Get-CimClass -Namespace root/cimv2 | Select-Object -First 20 CimClassName
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
Get-WinEvent -LogName Microsoft-Windows-WMI-Activity/Operational -MaxEvents 30`,
  "lsa-authentication-logon-sessions-credential-guard": String.raw`Get-CimInstance Win32_LogonSession |
  Select-Object LogonId, LogonType, AuthenticationPackage, StartTime
klist.exe sessions
Get-CimInstance Win32_DeviceGuard`,
  "job-objects-silos-containers": String.raw`!job
!process 0 1
dt nt!_EJOB <job-address>
# Compare nested job limits with documented QueryInformationJobObject output.`,
  "peb-teb-loader-thread-state": String.raw`!peb
!teb
dt ntdll!_PEB @$peb
dt ntdll!_TEB @$teb`,
  "windows-thread-pools-worker-factories": String.raw`!tp
!handle 0 3
~* k
# Correlate callback objects, worker threads, cleanup, and module lifetime.`,
  "dispatcher-objects-synchronization-irql": String.raw`!locks
!handle 0 3
!thread <waiting-thread>
!deadlock`,
  "kuser-shared-data-time-version-mitigations": String.raw`dt nt!_KUSER_SHARED_DATA 0xfffff78000000000
dps 0xfffff78000000000 L20
vertarget`,
  "win32k-user-gdi-sessions-attack-surface": String.raw`!session
lm m win32k*
!process 0 1
Get-Process | Select-Object Name, Id, SessionId`,
};

const topicCopy = {
  "windows-privesc": {
    label: "Windows Privilege Escalation",
    intro:
      "This lesson treats local elevation as a verifiable trust-boundary chain. It does not begin with a payload. It begins with the caller's real token, the object the caller can influence, the privileged component that consumes that object, and the operation that would produce a stronger security context.",
    question:
      "Which lower-privileged input can reach which privileged consumer, under what exact configuration, and what evidence would disprove the chain?",
    lab: "Use a disposable Windows 11 virtual machine with a standard-user test account and a separate administrator account. Inspect only resources you create or systems you are explicitly authorized to assess. The exercises collect configuration and telemetry; they do not deploy an escalation payload.",
    commands: `# Run from a standard-user PowerShell console
whoami /all
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
Get-Date -Format o`,
    evidence: `{
  "actor": "standard-user token captured with whoami /all",
  "controlled_object": "record exact path, key, task, service, pipe, or policy",
  "consumer": "record image, account, trigger, and Windows build",
  "sink": "state the expected privileged operation without executing it",
  "negative_control": "repeat after removing the writable or reachable condition"
}`,
    references: [
      "https://learn.microsoft.com/windows/security/identity-protection/access-control/access-control",
      "https://learn.microsoft.com/windows/win32/secauthz/access-control",
      "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers",
      "https://learn.microsoft.com/sysinternals/",
      "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/",
      "https://attack.mitre.org/tactics/TA0004/",
      "https://msrc.microsoft.com/update-guide/",
      "https://github.com/gtworek/Priv2Admin",
    ],
  },
  "malware-c2": {
    label: "Malware and C2 Analysis",
    intro:
      "This lesson separates observation from attribution. A sample or framework label is only an index. The useful model records state transitions across file structure, process execution, memory, persistence, network protocol, task semantics, and telemetry, while keeping every experiment inside a controlled analysis boundary.",
    question:
      "What changed, which component caused the change, which sensor observed it, and what alternative explanation or sensor gap could produce the same record?",
    lab: "Use an approved isolated malware-analysis environment with snapshots, synthetic credentials, controlled networking, and non-production hardware. Prefer benign fixtures and inert byte sequences. Do not connect an unknown sample to the public Internet or implement a deployable payload, listener, persistence mechanism, or evasion chain.",
    commands: `# Static intake only; do not execute the specimen
$sample = ".\\fixtures\\owned-sample.bin"
Get-FileHash -Algorithm SHA256 $sample
Get-Item $sample | Select-Object Length, CreationTimeUtc, LastWriteTimeUtc
Get-AuthenticodeSignature $sample | Select-Object Status, StatusMessage`,
    evidence: `{
  "hypothesis": "state one behavior before detonation",
  "fixture": "hash, size, provenance, and handling classification",
  "host_evidence": ["process", "file", "registry", "memory"],
  "network_evidence": ["DNS", "flow", "TLS", "application protocol"],
  "coverage_test": "prove each sensor was healthy with a benign control"
}`,
    references: [
      "https://learn.microsoft.com/windows/win32/debug/pe-format",
      "https://learn.microsoft.com/sysinternals/downloads/sysmon",
      "https://learn.microsoft.com/defender-endpoint/",
      "https://attack.mitre.org/techniques/enterprise/",
      "https://yara.readthedocs.io/en/stable/",
      "https://github.com/mandiant/flare-vm",
      "https://github.com/REMnux",
      "https://github.com/mandiant/capa",
    ],
  },
  "windows-internals": {
    label: "Windows Internals",
    intro:
      "This lesson builds a mechanism-first model of Windows. Public contracts, observable implementation behavior, and version-specific internal fields are kept separate. Structures and debugger output are evidence for a particular build, not timeless ABI promises.",
    question:
      "Which manager owns the object or state, how is it created and referenced, where is the user-to-kernel or subsystem boundary, and which facts change across Windows builds?",
    lab: "Use a disposable Windows debugging VM with matching Microsoft public symbols. Begin with user-mode inspection and documented APIs. Kernel debugger commands are read-only and should never be run against a production system. Record the exact OS build before interpreting undocumented structures.",
    commands: `# Establish version and symbol context before interpreting fields
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber
Get-CimInstance Win32_OperatingSystem | Select-Object Version, BuildNumber
# In WinDbg: verify symbols, then use read-only inspection
.symfix
.reload /f
vertarget`,
    evidence: `{
  "build": "edition, architecture, build, cumulative update",
  "public_contract": "documented API, WDK contract, or specification",
  "observation": "debugger or trace result with symbol provenance",
  "inference": "mechanism inferred from the observation",
  "version_risk": "field, policy, or path likely to change"
}`,
    references: [
      "https://learn.microsoft.com/windows-hardware/drivers/",
      "https://learn.microsoft.com/windows-hardware/drivers/debugger/",
      "https://learn.microsoft.com/windows/win32/sysinfo/windows-system-information",
      "https://learn.microsoft.com/sysinternals/",
      "https://github.com/winsiderss/systeminformer/tree/master/phnt",
      "https://ntdoc.m417z.com/",
      "https://www.vergiliusproject.com/",
      "https://github.com/reactos/reactos",
    ],
  },
};

function trackFor(topic, order) {
  for (const [end, track] of trackRanges[topic]) {
    if (order <= end) return track;
  }
  throw new Error(`No track for ${topic} lesson ${order}`);
}

function placementsFor(slug) {
  return Object.entries(sequences)
    .map(([topic, slugs]) => {
      const index = slugs.indexOf(slug);
      if (index === -1) return null;
      const order = index + 1;
      return { topic, track: trackFor(topic, order), order };
    })
    .filter(Boolean);
}

function titleFor(slug, sourceEntries) {
  return titleOverrides[slug] ?? sourceEntries[0]?.title ?? slug;
}

function difficultyFor(placements) {
  if (placements.some(({ order }) => order <= 2)) return "Foundation";
  if (
    placements.some(
      ({ topic, order }) =>
        (topic === "windows-internals" && order >= 21) ||
        (topic === "malware-c2" && order >= 8),
    )
  ) {
    return "Advanced";
  }
  return "Intermediate";
}

function primaryPlacement(slug, placements) {
  const preferredTopic = {
    "amsi-defender-scanning-boundaries-hardening": "malware-c2",
    "access-tokens-sids-integrity-privileges": "windows-internals",
  }[slug];
  return (
    placements.find(({ topic }) => topic === preferredTopic) ?? placements[0]
  );
}

function yamlList(items, indent = "") {
  return items.map((item) => `${indent}- ${JSON.stringify(item)}`).join("\n");
}

const trackCopy = {
  "windows-internals": {
    "processes-execution": {
      focus:
        "Follow identity and lifetime separately: a process owns an address space and handle table, a thread is the schedulable execution context, and either object can outlive a user-visible identifier through retained references.",
      evidence: [
        "Documented process and thread query APIs",
        "Version-matched WinDbg process, thread, token, wait, and stack views",
        "Kernel process/thread/image ETW with loss counters retained",
        "Handle, reference, cancellation, and teardown observations",
      ],
      versionRisk:
        "EPROCESS, ETHREAD, KTHREAD, worker-factory, scheduler, and mitigation fields are implementation details. Record the exact build, architecture, and symbol provenance before naming a field or offset.",
      readerGoal:
        "Explain who owns the state, which object carries it, which reference keeps it alive, and which transition a scheduler or executive component performs.",
    },
    "memory-manager": {
      focus:
        "Separate virtual address description, committed backing, page-table state, residency, mapped-section provenance, and allocator metadata. They answer different questions even when tools display them on one screen.",
      evidence: [
        "VirtualQuery, memory-map, section, and working-set APIs",
        "VAD, PTE, section, control-area, and working-set debugger views",
        "Protection, backing file, commit, dirty, and copy-on-write transitions",
        "Page heap, Special Pool, verifier, allocation stacks, and first-fault evidence",
      ],
      versionRisk:
        "PTE encodings, VAD layouts, heap backends, pool allocators, metadata hardening, and debugger extensions evolve across releases. Treat public layouts as build-specific references until confirmed.",
      readerGoal:
        "Trace one address from region ownership through backing and residency to the operation that changed its protection, contents, or lifetime.",
    },
    "security-objects": {
      focus:
        "Model authorization as an access request evaluated with a particular token against a particular securable object. Identity labels, granted handle rights, object lifetime, and impersonation state must remain distinct.",
      evidence: [
        "TokenInformationClass and documented authorization APIs",
        "Security descriptors, mandatory labels, requested masks, and granted masks",
        "Process primary-token and thread impersonation-token observations",
        "Object namespace, handle-table, and reference-lifetime evidence",
      ],
      versionRisk:
        "Documented access rights are more stable than token/object implementation layouts. New token attributes, mitigations, isolation modes, and container boundaries can change effective behavior without changing an account name.",
      readerGoal:
        "Reconstruct the complete access decision and show why a name, SID, handle value, or integrity level alone is insufficient evidence.",
    },
    "io-drivers": {
      focus:
        "Start at the exposed device interface and follow an I/O request through access checks, buffering, queue ownership, dispatch, completion, cancellation, Plug and Play, power, and teardown.",
      evidence: [
        "Device interfaces, symbolic links, service configuration, and ACLs",
        "IOCTL access bits, METHOD_* buffering, input/output lengths, and IRP state",
        "WDM dispatch or KMDF queue/callback configuration",
        "Driver Verifier, I/O verification, stack traces, and completion/cancel evidence",
      ],
      versionRisk:
        "Framework versions, queue policy, default device security, verifier rules, pool APIs, and internal IRP or framework-object layouts vary. Prefer WDK contracts and exact target observations.",
      readerGoal:
        "Draw the request lifecycle and identify the component responsible for every buffer, reference, callback, and failure path.",
    },
    "ipc-services": {
      focus:
        "Treat IPC as a protocol boundary with endpoint discovery, namespace security, connection identity, message schema, transferred objects, impersonation rules, cancellation, and disconnect lifetime.",
      evidence: [
        "Endpoint names, namespace placement, and security descriptors",
        "Client/server identities, authentication, impersonation level, and access masks",
        "Message sizes, attributes, handles, shared views, and state transitions",
        "RPC, ALPC, pipe, COM, service, ETW, and process-correlation evidence",
      ],
      versionRisk:
        "Undocumented port names, message layouts, COM registration behavior, service hosting, RPC defaults, and broker policy can change with builds and configuration. Confirm the live endpoint.",
      readerGoal:
        "Explain how one client-controlled message reaches one server decision and what proves the server consumed it under the claimed authority.",
    },
    "telemetry-runtime": {
      focus:
        "Separate event production from session control, buffering, transport, decoding, retention, and analysis. A missing record is meaningful only after the complete collection path is proven healthy.",
      evidence: [
        "Provider identity, event descriptor, keywords, levels, and enablement",
        "Session buffer, clock, stack-walk, file, and loss settings",
        "Manifest, TraceLogging, MOF, WPP, or runtime decoder provenance",
        "A benign control joined to debugger, API, or secondary telemetry",
      ],
      versionRisk:
        "Provider manifests, event versions, decoder schemas, debugger behavior, exception metadata, WoW64 transitions, and WMI providers vary. Preserve raw records and the decoder version.",
      readerGoal:
        "Prove which component emitted the record, which session retained it, how it was decoded, and which independent observation supports the interpretation.",
    },
    "kernel-platform": {
      focus:
        "Analyze platform protection as several independent enforcement boundaries: code admission, virtualization-protected policy, integrity of selected kernel state, isolation, and hardware-assisted control flow.",
      evidence: [
        "Effective Device Guard, VBS, HVCI, code-integrity, and boot state",
        "Loaded-image signatures, policy identifiers, and CodeIntegrity events",
        "Hypervisor, Secure Boot, CET, CFG, and process mitigation observations",
        "Version-matched symbols and supported diagnostics instead of bypass assumptions",
      ],
      versionRisk:
        "Hardware support, edition, boot configuration, servicing state, firmware, policy deployment, compatibility mode, and opt-in process settings all affect the real boundary.",
      readerGoal:
        "Name exactly which protection makes which decision and avoid collapsing DSE, HVCI, VBS, PatchGuard, CFG, or CET into one generic mitigation.",
    },
    "boot-architecture": {
      focus:
        "Follow the chain of trust phase by phase: firmware, boot manager, loader, kernel initialization, Session Manager, Wininit, services, and interactive logon each consume different policy and evidence.",
      evidence: [
        "Firmware, Secure Boot, TPM/measured-boot, and BCD state",
        "Boot manager, winload, kernel, ELAM, Code Integrity, and VBS logs",
        "SMSS, Wininit, SCM, service, and session creation evidence",
        "The earliest failed phase with exact status, component, and persistent input",
      ],
      versionRisk:
        "Firmware behavior, boot applications, BCD interpretation, ELAM, hypervisor startup, Secure Boot policy, and recovery paths differ across hardware and Windows releases.",
      readerGoal:
        "Locate the earliest trust decision that explains the observed later state instead of starting investigation after the desktop appears.",
    },
  },
  "windows-privesc": {
    foundations: {
      focus:
        "Represent elevation as a graph from a real low-privilege token to a stronger security context. Every edge needs actor control, consumer reachability, a trigger, and a privileged effect.",
      evidence: [
        "Standard-user token, integrity, groups, privileges, and session",
        "Controlled object plus exact writable or management rights",
        "Privileged consumer identity, trigger, and resulting operation",
        "Positive and negative controls recorded on the same build",
      ],
      versionRisk:
        "Account type, UAC policy, linked tokens, service isolation, application control, VBS, and cumulative updates change the graph. Do not inherit a chain from another host.",
      readerGoal:
        "Reject scanner shorthand and explain every trust-boundary edge in a form another researcher can reproduce safely.",
    },
    "discovery-evidence": {
      focus:
        "Enumeration produces leads. Convert each lead into a narrow hypothesis and preserve enough identity, ACL, configuration, runtime, and control evidence to accept or reject it.",
      evidence: [
        "Raw discovery output with tool version, time, and execution token",
        "Native ACL or management API results rather than color-coded labels",
        "Consumer process, account, configuration origin, and trigger",
        "Decision record containing alternatives and falsification evidence",
      ],
      versionRisk:
        "Scanner rules, privilege mappings, defaults, service configuration, policy sources, and Windows protections evolve. Re-evaluate the native condition on the tested machine.",
      readerGoal:
        "Turn one automated finding into a reproducible claim without treating tool severity as root-cause or exploitability evidence.",
    },
    "service-boundaries": {
      focus:
        "Separate service-object rights, registry representation, executable and DLL paths, referenced dependencies, account privileges, triggers, and restart reachability.",
      evidence: [
        "SCM security descriptor and granted service access rights",
        "ImagePath, ServiceDll, account, start mode, dependencies, and triggers",
        "Filesystem ACLs for every parsed executable or dependency candidate",
        "Start/restart authority, boot timing, failure actions, and service telemetry",
      ],
      versionRisk:
        "Service hardening, per-service SIDs, svchost splitting, trigger-start behavior, protected services, path parsing, and installer policy vary by build and configuration.",
      readerGoal:
        "Prove that the standard user controls material a stronger service actually consumes and can reach the relevant lifecycle transition.",
    },
    "token-ipc": {
      focus:
        "Treat impersonation chains as identity transfer across a real IPC or authentication boundary. A privileged client connection, permitted impersonation level, token type, and usable privilege are separate prerequisites.",
      evidence: [
        "Server endpoint ACL and attacker process/thread token",
        "Origin and security context of the connecting privileged client",
        "Impersonation level, token type, privileges, session, and restrictions",
        "Revert, duplicate, access-check, and negative-control observations",
      ],
      versionRisk:
        "COM/RPC activation, authentication protections, session isolation, service privileges, token restrictions, and patched coercion paths invalidate many named technique variants.",
      readerGoal:
        "Name the exact coercion and impersonation primitives instead of reporting a Potato-family tool name as the mechanism.",
    },
    "policy-controls": {
      focus:
        "Distinguish configured value, policy source, audit mode, enforcement point, scope, precedence, and runtime decision. A visible setting is not necessarily effective policy.",
      evidence: [
        "Local, domain, MDM, registry, and runtime policy origins",
        "Audit versus enforcement events from the deciding component",
        "Publisher, path, hash, script, DLL, driver, and interpreter coverage",
        "Benign allowed/blocked controls executed under the claimed token",
      ],
      versionRisk:
        "Policy schema, managed-installer state, reputation services, script hosts, rule options, defaults, and servicing behavior change. Record effective policy identifiers and OS build.",
      readerGoal:
        "Show which enforcement engine evaluated which artifact under which rule, then identify the narrow policy gap without calling every bypass an elevation.",
    },
    "execution-persistence": {
      focus:
        "A persistence location is a stored edge to a future consumer. Prove writer control, resolution precedence, trigger recurrence, consumer identity, and resulting execution context.",
      evidence: [
        "Exact registry key, file, COM class, task, service, or startup location",
        "Writer identity plus before/after content and ACL evidence",
        "Resolution, parsing, bitness, environment, and dependency behavior",
        "Trigger event, consumer process tree, resulting token, and cleanup proof",
      ],
      versionRisk:
        "Packaged activation, COM lookup, loader search, task schema, autorun policy, service hardening, and application control can change reachability across systems.",
      readerGoal:
        "Differentiate writable configuration from a recurring execution chain and document the first point where stronger authority is actually gained.",
    },
    "credentials-recovery": {
      focus:
        "Separate credential metadata, protected blob, key hierarchy, caller scope, logon material, backup or recovery path, and the privilege needed to read or decrypt each layer.",
      evidence: [
        "Owner SID, logon type, token, credential type, and storage scope",
        "Blob, master-key, machine/user, domain backup, and policy identifiers",
        "PPL, Credential Guard, VBS, LSASS, provider, and package state",
        "Self-created test secret with successful and failed recovery controls",
      ],
      versionRisk:
        "Authentication packages, logon types, DPAPI roaming, password changes, domain policy, PPL, Credential Guard, and virtualization-backed protections affect recoverability.",
      readerGoal:
        "Explain exactly which secret exists, where it is protected, what context can recover it, and which stronger boundary would have to be crossed.",
    },
    "lateral-boundaries": {
      focus:
        "Separate identity coercion, transport authentication, relay compatibility, target authorization, remote execution or management semantics, and durable artifacts.",
      evidence: [
        "Source identity and the service or machine induced to authenticate",
        "Protocol signing, channel binding, SPN, TLS, and authentication method",
        "Target endpoint authorization and the exact accepted operation",
        "Host, network, directory, certificate, WMI, or WSL artifacts joined in time",
      ],
      versionRisk:
        "Protocol hardening, endpoint configuration, domain functional state, certificate templates, DCOM changes, WSL architecture, and cumulative updates alter the chain.",
      readerGoal:
        "Stop at the strongest proven remote effect and do not equate a coerced authentication, successful relay, and code execution.",
    },
  },
  "malware-c2": {
    foundations: {
      focus:
        "Treat analysis as a controlled measurement process: preserve the specimen, state a falsifiable behavior hypothesis, prove every sensor, bound execution, and reset to a known state.",
      evidence: [
        "Hash, size, provenance, signature, handling class, and immutable original",
        "Snapshot, network simulation, time source, credentials, and containment state",
        "Healthy process, file, registry, memory, DNS, flow, TLS, and protocol sensors",
        "Timeline, negative control, disposal record, and confidence decision",
      ],
      versionRisk:
        "Guest build, analysis tooling, hypervisor artifacts, time, network simulation, Defender policy, and sample configuration change behavior and visibility.",
      readerGoal:
        "Produce a repeatable experiment whose observations can be distinguished from sandbox artifacts, collection gaps, and analyst assumptions.",
    },
    "static-analysis": {
      focus:
        "Move from container and file structure to bounded capability claims. Validate offsets, sizes, encodings, imports, relocations, signatures, metadata, and parser assumptions before interpreting strings.",
      evidence: [
        "Cryptographic hash, exact bytes, file type, container members, and provenance",
        "Bounds-checked headers, sections, imports, exports, resources, and overlays",
        "Strings with encoding, location, references, and surrounding control flow",
        "Compiler, library, packer, rule, and capability claims with hard negatives",
      ],
      versionRisk:
        "Parser versions, format extensions, compiler output, signatures, YARA modules, packed variants, and document features change interpretation. Preserve tool versions and raw bytes.",
      readerGoal:
        "Explain what the artifact can support without claiming that a static capability executed during the observed incident.",
    },
    "dynamic-analysis": {
      focus:
        "Build a synchronized state-transition timeline across process, file, registry, service, task, WMI, memory, DNS, transport, and application-protocol evidence.",
      evidence: [
        "Pre-execution snapshot and one explicit behavior hypothesis",
        "Process/thread/image, file, registry, service, task, and WMI telemetry",
        "Memory regions, protections, writes, imports, call stacks, and control transfers",
        "DNS, flow, TLS, request/response, simulated service, and sensor-health records",
      ],
      versionRisk:
        "Sample configuration, privileges, locale, clock, network responses, EDR hooks, Defender state, anti-analysis checks, and guest build can fork execution.",
      readerGoal:
        "State what happened during this execution, what did not receive coverage, and which alternate environment could produce a different path.",
    },
    "memory-execution": {
      focus:
        "Follow the executable-content lifecycle: origin, decode or reconstruction, allocation or mapping, writes, relocations/imports, protection change, execution transfer, and cleanup.",
      evidence: [
        "Source bytes, decoder stub, reconstruction writes, and unpacking transition",
        "Private or section-backed regions, protection history, and mapped provenance",
        "Thread start, APC, callback, context, call stack, and target-process relationship",
        "Dump limitations, unresolved imports, anti-debug influence, and negative controls",
      ],
      versionRisk:
        "Architecture, calling convention, CFG, CET, ACG, DEP, ASLR, loader behavior, EDR instrumentation, and process policy constrain executable-memory chains.",
      readerGoal:
        "Describe the smallest observable execution primitive and keep loader capability, reconstructed code, and behavior actually executed as separate claims.",
    },
    "c2-operations": {
      focus:
        "Model command and control as identity, transport, message direction, correlation, retry, tasking, result, server state, extension, and operator boundaries—not a product label.",
      evidence: [
        "Agent identity, enrollment, keys, configuration, and server-side state",
        "DNS, flow, TLS, HTTP or other protocol fields with timing and direction",
        "Task identifier, payload or command semantics, acknowledgements, and results",
        "Host execution joined to transport records and a benign protocol simulator",
      ],
      versionRisk:
        "Framework version, profile, agent build, extension set, listener configuration, TLS stack, redirector, infrastructure, and network middleware change observables.",
      readerGoal:
        "Extract protocol and task invariants that survive superficial profile changes while avoiding signatures based only on names or one request shape.",
    },
    "execution-persistence": {
      focus:
        "Separate initial execution, privilege context, persistence storage, trigger, consumer, asynchronous service state, transfer job, and later recurrence.",
      evidence: [
        "Writer and stored object with before/after state",
        "Task, service, BITS, WMI, registry, startup, or Linux consumer configuration",
        "Trigger time, process ancestry, token, network activity, and resulting artifacts",
        "Reboot/logon/session controls plus cleanup and recurrence verification",
      ],
      versionRisk:
        "BITS queue format, WMI repository behavior, task/service policy, WSL architecture, systemd precedence, application control, and telemetry differ across environments.",
      readerGoal:
        "Prove recurrence under the intended identity and lifecycle event instead of labeling a stored artifact as established persistence.",
    },
    "detection-engineering": {
      focus:
        "Turn a behavior model into a testable analytic with explicit data requirements, joins, time bounds, exclusions, coverage controls, performance limits, and retirement criteria.",
      evidence: [
        "Stable behavior invariant and the smallest required event fields",
        "Healthy source, provider, parser, clock, retention, and loss evidence",
        "Representative positives, hard negatives, near misses, and environment variants",
        "Precision, recall proxy, cost, triage context, owner, review date, and rollback",
      ],
      versionRisk:
        "Provider schemas, Defender features, AMSI hosts, logging policy, YARA engine, application control, product versions, and normal fleet behavior evolve.",
      readerGoal:
        "Ship an analytic another defender can test, understand, tune, and retire without depending on folklore or a single indicator.",
    },
  },
};

function makeBody({
  slug,
  title,
  sourceEntries,
  placements,
  primary,
  mechanics,
}) {
  const copy = topicCopy[primary.topic];
  const track = trackCopy[primary.topic]?.[primary.track];
  const frameByTopic = {
    "windows-privesc": {
      labels: ["Starting state", "Privilege decision", "Reachability", "Proof"],
      flow: "lower-privileged actor → controlled input → privileged consumer → trigger → measurable effect",
      rule: "A writable object is only the first edge. The chain is incomplete until the privileged consumer, trigger, resulting context, and negative control are all known.",
      stagePrompts: [
        "Capture the caller's actual token and the exact object the caller controls. Do not substitute an administrator-shell result or a scanner label.",
        "Locate the stronger component that makes the decisive access, parsing, loading, authentication, or execution decision.",
        "Prove the caller can reach the consumer and trigger on this host without borrowing the privilege the finding is supposed to obtain.",
        "Join configuration and runtime evidence, then remove one prerequisite and confirm that the predicted privileged transition disappears.",
      ],
      falsifiers: [
        "The standard-user token lacks the claimed control, or the controlled object is not the object used by the consumer.",
        "The privileged component never reads, resolves, authenticates, loads, or executes the controlled material.",
        "Policy, ACL, path precedence, session, architecture, service state, or trigger timing blocks the chain.",
        "The same effect remains after the required condition is removed, or the resulting context is not stronger than the starting token.",
      ],
      detection: [
        "Record the writer identity and the exact object changed.",
        "Correlate that change with the privileged consumer and its trigger.",
        "Alert on the joined transition rather than a utility name by itself.",
        "Harden the earliest reachable edge: permissions, policy, trigger, or consumer identity.",
      ],
      caseOpening:
        "A scanner reports a possible elevation path after finding one suspicious permission or policy value.",
    },
    "malware-c2": {
      labels: [
        "Observable artifact",
        "Behavior boundary",
        "Execution constraint",
        "Correlated evidence",
      ],
      flow: "artifact → parser or runtime → state transition → host/network evidence → bounded conclusion",
      rule: "A family or framework label is an index, not an explanation. The useful result is the smallest behavior claim supported by healthy, time-aligned sensors.",
      stagePrompts: [
        "Preserve the original artifact and describe the exact bytes, metadata, memory, request, or record that begins the hypothesis.",
        "Identify the parser, loader, runtime, service, operating-system component, or protocol peer that turns the artifact into behavior.",
        "Record architecture, policy, privileges, configuration, timing, network responses, and anti-analysis conditions that select the observed path.",
        "Correlate independent host and network sources on one timeline and prove each sensor with a benign event before interpreting silence.",
      ],
      falsifiers: [
        "The artifact is common compiler, library, administrative, or protocol material and does not carry the claimed behavior.",
        "The expected parser, runtime, loader, service, or peer never consumes the artifact during the observed execution.",
        "A required architecture, configuration, key, response, privilege, policy, or timing condition is absent.",
        "Independent telemetry contradicts the transition, the sensor fails its health control, or the behavior cannot be repeated from a clean snapshot.",
      ],
      detection: [
        "Join file or memory provenance with the process and thread transition it caused.",
        "Correlate host behavior with DNS, flow, TLS, and application-protocol timing.",
        "Test every sensor with a benign control before interpreting silence.",
        "Harden execution, credential, egress, and logging boundaries independently.",
      ],
      caseOpening:
        "An analyst assigns a malware or C2 label from one string, process name, memory characteristic, or network indicator.",
    },
    "windows-internals": {
      labels: [
        "Owned state",
        "Manager or boundary",
        "Versioned constraint",
        "Observable evidence",
      ],
      flow: "owner or manager → object/state → transition → lifetime rule → version-matched observation",
      rule: "Documented contracts, symbol-backed observations, and reverse-engineered implementation details have different stability. Keep those evidence classes separate.",
      stagePrompts: [
        "Name the executive manager, subsystem, process, driver, service, or runtime that owns the state; then separate that state from the handle or identifier used to find it.",
        "Trace creation, lookup, access, mutation, queueing, completion, reference ownership, cancellation, and teardown across the actual subsystem boundary.",
        "Record build, architecture, symbols, policy, mitigation state, and every undocumented layout assumption before interpreting internal fields.",
        "Correlate a documented API or contract with debugger, trace, object, or memory evidence and retain enough provenance to reproduce the observation.",
      ],
      falsifiers: [
        "The displayed identifier, handle, field, or list entry refers to a different object or a stale/reused lifetime.",
        "The presumed manager does not perform the transition, or another layer owns the decisive state and synchronization.",
        "The layout, policy, mitigation, architecture, or code path does not match the tested Windows build.",
        "A documented query, independent trace, or negative control contradicts the debugger-derived interpretation.",
      ],
      detection: [
        "Use version-matched symbols and retain the exact build with every debugger observation.",
        "Correlate public API results, object state, and trace output instead of trusting one internal field.",
        "Track creation, references, asynchronous work, cancellation, and teardown as one lifecycle.",
        "Treat a missing field or command on another build as a version result, not permission to guess.",
      ],
      caseOpening:
        "A debugger command displays an interesting field and the first interpretation treats it as a universal Windows rule.",
    },
  };
  const frame = frameByTopic[primary.topic];
  if (!copy || !track || !frame) {
    throw new Error(`Missing professional lesson frame for ${slug}`);
  }

  const mechanismParts = mechanics
    .split(";")
    .map((part) => part.trim().replace(/[.]+$/, ""));
  if (mechanismParts.length !== 4) {
    throw new Error(`Expected four mechanism clauses for ${slug}`);
  }

  const inspectionProbe = inspectionProbes[slug];
  if (!inspectionProbe) {
    throw new Error(`Missing topic-specific inspection probe for ${slug}`);
  }

  const glossaryCandidates = [
    [
      /access token/i,
      "Access token",
      "A kernel-managed security context describing an identity, its groups, privileges, integrity level, restrictions, and selected policy state.",
    ],
    [
      /\bSIDs?\b/i,
      "SID",
      "A stable security identifier used by Windows to represent a user, group, service, package, capability, or other security principal.",
    ],
    [
      /\bDACLs?\b|access control list/i,
      "DACL",
      "The ordered access-control entries Windows evaluates to allow or deny requested rights on a securable object.",
    ],
    [
      /integrity level/i,
      "Integrity level",
      "A mandatory label used by Mandatory Integrity Control to constrain write-like interactions across integrity boundaries.",
    ],
    [
      /impersonat/i,
      "Impersonation",
      "A thread temporarily evaluates security using a client token while the process primary token remains a separate security context.",
    ],
    [
      /named pipe/i,
      "Named pipe",
      "A Windows IPC endpoint with namespace placement, a security descriptor, server/client identities, and message or byte-stream semantics.",
    ],
    [
      /\bALPC\b/i,
      "ALPC",
      "The kernel-backed local IPC facility used by many services and brokers for messages, attributes, handle transfer, and shared views.",
    ],
    [
      /\bRPC\b/i,
      "RPC",
      "A protocol and runtime that marshals a client's procedure request to a server endpoint with authentication and authorization policy.",
    ],
    [
      /\bCOM\b/i,
      "COM",
      "An activation and interface model whose registration, activation context, bitness, server type, and security determine the actual execution boundary.",
    ],
    [
      /service control manager|\bSCM\b/i,
      "Service Control Manager",
      "The privileged manager that stores service configuration, starts service processes, sends controls, and authorizes service-object operations.",
    ],
    [
      /\bLSASS\b|local security authority/i,
      "LSASS",
      "The user-mode security service process that hosts LSA policy and authentication packages and maintains logon-session state.",
    ],
    [
      /\bDPAPI\b/i,
      "DPAPI",
      "Windows data protection tied to a user or machine master-key hierarchy and the caller's logon and protection context.",
    ],
    [
      /\bUAC\b|user account control/i,
      "UAC",
      "The elevation-consent system that mediates use of an administrator's linked filtered and elevated tokens.",
    ],
    [
      /\bWMI\b/i,
      "WMI",
      "The management infrastructure connecting CIM namespaces and classes to providers, repository state, remote transport, and eventing.",
    ],
    [
      /\bETW\b/i,
      "ETW",
      "A high-throughput tracing system composed of providers, controller-managed sessions, buffers, event metadata, and consumers.",
    ],
    [
      /\bAMSI\b/i,
      "AMSI",
      "An interface through which participating applications submit content and metadata to a registered antimalware provider.",
    ],
    [
      /\bWFP\b|windows firewall/i,
      "Windows Filtering Platform",
      "The layered filtering engine behind Windows firewall policy, filters, providers, sublayers, and callouts.",
    ],
    [
      /\bIRP\b/i,
      "IRP",
      "An I/O request packet carrying an operation through driver dispatch, queueing, completion, cancellation, and teardown.",
    ],
    [
      /\bIOCTL\b/i,
      "IOCTL",
      "A device-control request whose control code, required handle access, buffering method, input, and output define a driver boundary.",
    ],
    [
      /\bKMDF\b|\bWDM\b/i,
      "Windows driver model",
      "The contracts and lifecycles connecting drivers, devices, queues, callbacks, Plug and Play, power, and I/O.",
    ],
    [
      /\bIRQL\b/i,
      "IRQL",
      "A per-processor interrupt-priority level that constrains scheduling, synchronization, interruptibility, and pageable-code access.",
    ],
    [
      /\bDPCs?\b/i,
      "DPC",
      "Deferred kernel work normally scheduled after an interrupt routine completes its time-critical processing.",
    ],
    [
      /\bAPCs?\b/i,
      "APC",
      "A queued callback delivered in a particular thread context under specific kernel, special-kernel, or user-mode rules.",
    ],
    [
      /\bVADs?\b/i,
      "VAD",
      "A kernel descriptor for a process virtual-address region, including its range, protection, commitment, and backing relationship.",
    ],
    [
      /page tables?|\bPTEs?\b/i,
      "Page table entry",
      "The architecture-specific translation and state record for one virtual page; its software meanings are build dependent.",
    ],
    [
      /section objects?|mapped files?/i,
      "Section object",
      "Shared backing that can be mapped as image, file data, or pagefile-backed memory into one or more address spaces.",
    ],
    [
      /\bPEB\b/i,
      "PEB",
      "User-mode process environment state used by the loader and runtime; undocumented fields vary by architecture and Windows build.",
    ],
    [
      /\bTEB\b/i,
      "TEB",
      "Per-thread user-mode state including stack bounds, TLS, last-error information, and architecture-specific runtime fields.",
    ],
    [
      /\bWoW64\b/i,
      "WoW64",
      "The compatibility environment that runs 32-bit user-mode code on 64-bit Windows and translates selected views and transitions.",
    ],
    [
      /PatchGuard/i,
      "PatchGuard",
      "Kernel Patch Protection, which detects unsupported modification of selected critical kernel code or state.",
    ],
    [
      /\bHVCI\b/i,
      "HVCI",
      "Hypervisor-protected code integrity, which moves selected code-integrity policy and decisions behind a VBS boundary.",
    ],
    [
      /\bVBS\b/i,
      "VBS",
      "Virtualization-based security, which uses the hypervisor to isolate selected security services, policy, and data.",
    ],
    [
      /\bC2\b|command and control/i,
      "Command and control",
      "The identity, transport, tasking, result, retry, and server-state model used to control a remote agent.",
    ],
    [
      /shellcode/i,
      "Shellcode",
      "Position-independent machine code designed to execute without the normal executable-loader contract.",
    ],
    [
      /process injection/i,
      "Process injection",
      "A family of cross-process memory, handle, section, thread, APC, callback, or loader state transitions.",
    ],
    [
      /\bCOFF\b|beacon object file/i,
      "COFF object",
      "A relocatable object whose sections, symbols, and relocations must be resolved by a linker or in-memory host.",
    ],
    [
      /\bYARA\b/i,
      "YARA rule",
      "A byte- and structure-matching rule whose strings, modules, metadata, and condition determine match semantics and cost.",
    ],
    [
      /packer|packed malware/i,
      "Packer",
      "A loader transformation that stores original code or data in compressed or encrypted form and reconstructs it at runtime.",
    ],
    [
      /job objects?|silos?/i,
      "Job object",
      "A process grouping object used for resource limits, accounting, notifications, and coordinated lifecycle policy.",
    ],
    [
      /filter manager|minifilter/i,
      "Minifilter",
      "A Filter Manager driver registered at an altitude to observe or modify selected file-system operations.",
    ],
    [
      /\bVSS\b|shadow copy/i,
      "Volume Shadow Copy",
      "A coordinated snapshot mechanism involving requesters, writers, providers, and shadow-copy devices.",
    ],
  ];
  const glossaryFallbacks = [
    [
      "Mechanism",
      "The concrete state, component, decision, and transition that produce an observable result.",
    ],
    [
      "Trust boundary",
      "A point where data or control crosses into a component with different authority, ownership, or assumptions.",
    ],
    [
      "Evidence",
      "A recorded observation with enough identity, time, build, provenance, and collection context to support or challenge a claim.",
    ],
    [
      "Negative control",
      "A repeat of the experiment with one required condition removed, used to test causality and alternate explanations.",
    ],
  ];
  const glossaryEntries = glossaryCandidates
    .filter(([pattern]) => pattern.test(`${title} ${mechanics}`))
    .slice(0, 6)
    .map(([, term, definition]) => [term, definition]);
  for (const fallback of glossaryFallbacks) {
    if (glossaryEntries.length >= 6) break;
    glossaryEntries.push(fallback);
  }

  const placementSummary = placements
    .map(
      ({ topic, track: placementTrack, order }) =>
        `${topic} lesson ${String(order).padStart(2, "0")} in ${placementTrack}`,
    )
    .join("; ");
  const modelRows = mechanismParts
    .map(
      (part, index) =>
        `| ${index + 1}. **${frame.labels[index]}** | ${part}. | ${track.evidence[index]} |`,
    )
    .join("\n");
  const glossaryRows = glossaryEntries
    .map(([term, definition]) => `| **${term}** | ${definition} |`)
    .join("\n");
  const stageSections = mechanismParts
    .map(
      (part, index) => `### ${index + 1}. ${frame.labels[index]}

**Mechanism claim.** ${part}.

For **${title}**, this stage is where the write-up must become concrete. ${frame.stagePrompts[index]} The relevant evidence source for this stage is **${track.evidence[index].toLowerCase()}**. Preserve the complete result rather than copying only the field that appears to support the hypothesis.

**What can invalidate this ${frame.labels[index].toLowerCase()} stage.** For **${title}**, ${frame.falsifiers[index]} Treat that result as useful evidence because it narrows this article's mechanism and prevents the lead from becoming a universal security claim.

**Review question for ${frame.labels[index].toLowerCase()}.** Can another researcher identify the actor or owner, exact object or artifact, deciding component, required state, and timestamp for this stage of **${title}**? If not, this specific mechanism claim remains **UNVERIFIED**.`,
    )
    .join("\n\n");
  const evidenceRows = track.evidence
    .map(
      (source, index) =>
        `| ${frame.labels[index]} | ${source} | ${mechanismParts[index]}. | ${frame.falsifiers[index]} |`,
    )
    .join("\n");
  const detectionList = frame.detection
    .map((item, index) =>
      index === 0
        ? `- For **${title}**, ${item.charAt(0).toLowerCase()}${item.slice(1)}`
        : `- ${item}`,
    )
    .join("\n");
  const takeawayList = mechanismParts
    .map((part, index) => `- **${frame.labels[index]}:** ${part}.`)
    .join("\n");
  const sourceList = sourceEntries
    .map(
      ({ title: sourceTitle, url }) =>
        `| [${sourceTitle}](${url}) | Original lesson source | Establishes the source article's terminology and examples; re-check claims against primary documentation and the tested build. |`,
    )
    .join("\n");
  const genericReferences = [...new Set(copy.references)].map((url) => {
    const kind = url.includes("learn.microsoft.com")
      ? "Microsoft documentation"
      : url.includes("attack.mitre.org")
        ? "Knowledge base"
        : url.includes("github.com")
          ? "Source repository"
          : "Research reference";
    return { title: new URL(url).hostname + new URL(url).pathname, url, kind };
  });
  const referenceRows = genericReferences
    .map(
      ({ title: referenceTitle, url, kind }) =>
        `| [${referenceTitle}](${url}) | ${kind} | Use for contracts, terminology, tooling, or comparative context; it is not proof of the current target by itself. |`,
    )
    .join("\n");
  const fence = "```";

  return `> **Quick answer:** ${mechanismParts[0]}. The conclusion becomes defensible only when the remaining boundary, constraint, and evidence stages are verified on the named build and identity.

## Scope and evidence contract

${copy.intro} Applied to **${title}**, this method begins with the concrete statement that ${mechanismParts[0].toLowerCase()}.

This document treats **${title}** as a mechanism to reconstruct, not a label to memorize. Its curriculum placement is ${placementSummary}. That placement helps navigation; it does not imply that the behavior belongs to one security domain or that every environment exposes the same path.

The **${title}** track-specific focus is: ${track.focus} The practical objective for this article is to ${track.readerGoal.toLowerCase()}

Before using any internal field, configuration value, event, or public write-up as evidence for **${title}**, record the target's Windows edition, version, build and revision, architecture, symbol status, relevant policy and mitigation state, execution identity, and collection time. The confidence vocabulary below prevents this specific lesson from hiding uncertainty behind polished prose:

| State | Meaning in this lesson |
| --- | --- |
| **CONFIRMED** | Current-target evidence proves the claim and the expected negative control changes the result. |
| **LIKELY** | Multiple sources support the claim, but one decisive low-risk observation remains unavailable. |
| **UNVERIFIED** | The statement is plausible but depends on public references, a decompiler view, a scanner label, another build, or an untested configuration. |
| **REJECTED** | Current evidence or a control contradicts the proposed mechanism. |

## Architecture at a glance

Use this flow as the shortest complete map:

> **${frame.flow}**

${frame.rule} In **${title}**, the four stages resolve to ${frame.labels.join(" → ").toLowerCase()}, and each stage must point to the mechanism statement and evidence in the table below.

| Stage | Mechanism on this topic | Strongest first evidence |
| --- | --- | --- |
${modelRows}

For **${title}**, the table is a causal chain rather than a checklist of unrelated facts. Trace it backward from each ${frame.labels[3].toLowerCase()} observation to the actor and owned state, then forward through the ${frame.labels[1].toLowerCase()} decision, transition, cleanup, and failure path.

## Mechanism deep dive

${stageSections}

## Key terms in plain language

The terms below are intentionally scoped to **${title}**. They should not be used as synonyms: each names a different object, policy, boundary, or kind of evidence.

| Term | Precise working meaning |
| --- | --- |
${glossaryRows}

When public documentation and debugger terminology for **${title}** differ, retain both names and state which source supplied each one. Any debugger field used in this lesson is evidence for the recorded build, not automatically a stable ABI or security contract.

## Version and environment scope

${track.versionRisk} For **${title}**, the version-sensitive statement that must be rechecked first is: ${mechanismParts[2]}.

Record the following **${title}** dimensions before comparing two systems or importing an exploitability conclusion from another target:

| Dimension | Minimum record | Why it can change the answer |
| --- | --- | --- |
| Operating system | Edition, version, build, revision, update level | Code paths, defaults, layouts, services, telemetry, and mitigations change through servicing. |
| Architecture | x86, x64, ARM64, native or WoW64 view | Pointer width, calling convention, structure view, redirection, and available mitigations differ. |
| Identity | User and group SIDs, integrity, privileges, process token, thread token, session | The actor that can observe a condition may not be the actor that can reach or trigger it. |
| Policy | Effective local/domain/MDM/runtime source and enforcement mode | A visible registry value or UI setting may be overridden, merged, audited, or inactive. |
| Mitigations | VBS/HVCI, CFG/CET, DEP, ASLR, application control, PPL, sandbox policy as relevant | Exploitability and observability depend on actual opt-in, hardware, boot, and process state. |
| Symbols and tools | PDB identity, symbol path, debugger/parser/collector version | Offsets, names, schemas, and decoded fields are meaningful only with matching provenance. |
| Sensor health | Provider/session/channel, filters, loss, clock, retention, forwarding | Missing telemetry cannot support absence until a benign control proves the collection path. |
| Lifetime | Creation, references, asynchronous work, cancellation, teardown, cleanup | Stale handles, reused identifiers, queued callbacks, and delayed consumers can change object identity. |

Unknown values in a **${title}** decision record must remain explicitly **unknown**. Do not fill this article's gaps with defaults copied from documentation or another researcher's machine.

## Evidence matrix

For **${title}**, work from each mechanism claim to the least-invasive evidence source before choosing a tool:

| Claim stage | Preferred evidence | Observation that supports the claim | Observation that falsifies or narrows it |
| --- | --- | --- | --- |
${evidenceRows}

For **${title}**, a screenshot of one promising field is weaker than a reproducible evidence bundle. Preserve raw commands, complete output, exit status, actor token, object identity, timestamps, build, symbol or decoder provenance, and both controls named above.

## Safe guided lab

${copy.lab} The **${title}** exercise is limited to the read-only inspection probe and controls described below.

### 1. Establish the baseline

Run the **${title}** baseline from the identity and architecture named in the hypothesis. Use a fresh snapshot or purpose-built test object for this mechanism and save the output with an ISO-8601 timestamp.

${fence}powershell
${copy.commands}
${fence}

Baseline acceptance criteria for **${title}**:

- the **${title}** execution identity and Windows build are visible in the saved record;
- the test object, file, process, endpoint, provider, or specimen belongs to the lab;
- relevant policy and mitigation values are captured before the observation;
- no production secret, unknown binary, persistence payload, or destructive trigger is introduced.

### 2. Inspect the topic-specific mechanism

The **${title}** probe below is read-only. Replace placeholders only with a process, file, object, trace, or VM that belongs to the authorized lab. If an elevated debugger is needed to observe this mechanism, record that elevation separately; it does not prove a standard user can cause the same transition.

${fence}text
${inspectionProbe}
${fence}

Interpret the **${title}** output against ${frame.labels.join(", ").toLowerCase()} rather than a tool's severity label. If a field or command is unavailable on this target, record that as a version/tool result and do not import the missing value from another build.

### 3. Run a positive and negative control

For **${title}**, the positive control keeps every required precondition and predicts the ${frame.labels[3].toLowerCase()} observation. The negative control changes exactly one relevant variable—actor identity, object ACL, policy, architecture/view, consumer state, trigger, network response, or sensor configuration—while the remaining lab state stays stable.

| Control | Change | Expected result |
| --- | --- | --- |
| Positive | Preserve all four mechanism stages | The predicted transition appears in the primary and at least one corroborating source. |
| Negative | Remove one required condition | The transition disappears or changes in the way predicted by the model. |
| Sensor health | Generate a benign event with a known result | The collector records and decodes it without unexplained loss. |
| Cleanup | Revert the test object and repeat inspection | Persistent state returns to baseline and no queued work remains. |

### 4. Write the decision record

${fence}text
Title: ${title}
Claim:
Target: edition | version | build.revision | architecture
Identity: process token | thread token | integrity | privileges | session
Starting state:
Decision boundary:
Required condition:
Observed transition:
Primary evidence:
Corroborating evidence:
Contradictory evidence:
Benign control:
Negative control:
Version and policy caveats:
Cleanup result:
Confidence: CONFIRMED | LIKELY | UNVERIFIED | REJECTED
Next experiment and falsification criterion:
${fence}

The **${title}** lab is complete only when the controls explain its evidence. A dramatic tool label, isolated event, writable path, suspicious string, or debugger field cannot substitute for the four-stage mechanism.

## Worked case-study method

${frame.caseOpening} For **${title}**, treat that clue as a lead and review it through the same four stages:

1. **${frame.labels[0]}:** verify the current-target statement that ${mechanismParts[0]}.
2. **${frame.labels[1]}:** identify the component and decision described by this claim: ${mechanismParts[1]}.
3. **${frame.labels[2]}:** test the build, identity, policy, lifetime, and configuration constraint: ${mechanismParts[2]}.
4. **${frame.labels[3]}:** demand the joined observation described here: ${mechanismParts[3]}.

For **${title}**, stop at the strongest supported conclusion. If ${frame.labels[0].toLowerCase()} and ${frame.labels[1].toLowerCase()} are proven but ${frame.labels[2].toLowerCase()} is not, report a **dangerous condition** or **research lead**, not confirmed impact. If runtime evidence agrees but the sensor-health control fails, lower confidence. If the negative control does not change the result, revise this mechanism before collecting more screenshots.

A publication-quality **${title}** case study should include a target table, causal diagram, exact evidence excerpts, competing explanations, version scope, mitigation interaction, cleanup, limitations, and direct references. A second researcher must be able to reproduce this mechanism without relying on the original author's private intuition.

## Detection and hardening

${detectionList}

For the **${title}** detection model, correlate ${track.evidence.join(", ").toLowerCase()}. Join its state change to consumer activity and resulting effect within a justified time window, then document required fields, clock source, exclusions, expected volume, sensor-health control, and what this analytic cannot prove.

Hardening **${title}** should break the earliest edge that is both reachable and operationally safe to change. After changing the relevant permission, policy, service exposure, execution control, authentication, egress, or telemetry path, repeat this lesson's controls. **Mitigated** means the predicted transition no longer occurs under the original preconditions—not merely that a setting changed.

## Failure modes and review checklist

Use this checklist when reviewing a draft of **${title}**:

- Does the opening of **${title}** state the exact target, actor, object or artifact, consumer, constraint, and result?
- Are documented facts, current-target observations, and implementation inferences labeled separately?
- Does every internal structure, event schema, default, or policy claim carry build and source provenance?
- Is a handle or identifier kept separate from the underlying object and its lifetime?
- Is writable or suspicious state kept separate from consumer reachability and actual execution?
- Are static capability, configured capability, and behavior observed in one execution reported at different confidence levels?
- Does a benign control prove the sensor, and does a negative control test causality?
- Are cancellation, teardown, cleanup, failure behavior, and asynchronous work included?
- Are mitigations recorded as effective target state rather than assumed from product version?
- Could another researcher falsify the conclusion using the retained evidence?

A **${title}** draft that cannot answer these questions is not finished, regardless of its word count or number of screenshots.

## Takeaways

${takeawayList}

The durable **${title}** skill is not remembering one command. It is connecting each of this lesson's four mechanism statements to a target-specific observation, explaining what would disprove it, and repeating the test without silently changing the trust boundary.

## Check your understanding

<details>
  <summary>Can you explain ${title} without naming a tool?</summary>
  A strong answer follows ${frame.flow}. It names the owner or actor, controlled state, deciding component, required condition, transition, lifetime, and evidence.
</details>

<details>
  <summary>Which fact is most likely to change across Windows versions?</summary>
  For **${title}**, start with this track warning: ${track.versionRisk} Then
  replace the assumption with a current-target observation tied to
  **${mechanismParts[0]}**.
</details>

<details>
  <summary>What result would make you reject the model?</summary>
  Reject or revise the **${title}** model when its predicted transition survives
  removal of a required condition, the stated actor cannot reach
  **${mechanismParts[1]}**, object identity or lifetime is wrong, or an
  independent healthy source contradicts the claimed state.
</details>

## Limitations and next research

This **${title}** document does not claim that every Windows edition, patch level, architecture, policy set, hardware configuration, or product integration behaves identically. Its read-only lab is not exploitability proof, attribution, or a production authorization decision. The next useful experiment is the smallest safe observation that can move one named ${frame.labels.join("/").toLowerCase()} stage from **UNVERIFIED** to **LIKELY** or **CONFIRMED**, or reject it cleanly.

## References

### Source coverage and reliability

The **${title}** lesson consolidates the source material below. These pages and repositories provide context but cannot override current-target evidence. Any public structure layout, ReactOS/Wine behavior, debugger screenshot, blog-derived claim, or cross-build offset used here remains **UNVERIFIED** until checked against the tested binary, symbols, documented API, dump, or runtime trace.

| Source | Type | How it is used |
| --- | --- | --- |
${sourceList}
${referenceRows}

Accessed: **2026-07-28**.
`;
}

await mkdir(blogDirectory, { recursive: true });
const groupedCoverage = Map.groupBy(coverage, (entry) => entry.localSlug);
let generated = 0;

for (const [slug, sourceEntries] of groupedCoverage) {
  if (existing.has(slug)) continue;
  const mechanics = detailText[slug];
  if (!mechanics) throw new Error(`Missing lesson detail for ${slug}`);

  const placements = placementsFor(slug);
  if (!placements.length) throw new Error(`Missing placement for ${slug}`);
  const primary = primaryPlacement(slug, placements);
  const title = titleFor(slug, sourceEntries);
  const destination = path.join(blogDirectory, `${slug}.mdx`);

  try {
    await stat(destination);
    if (!overwriteGenerated) continue;
  } catch {
    // The lesson does not exist yet.
  }

  const description = `A plain-language, evidence-first guide to ${title}.`;
  const prerequisites =
    primary.topic === "windows-internals"
      ? [
          "Basic Windows processes, threads, tokens, and handles",
          "A disposable VM with matching public symbols",
        ]
      : primary.topic === "malware-c2"
        ? [
            "Basic Windows process, file, and network concepts",
            "An approved isolated analysis environment",
          ]
        : [
            "Basic Windows access-control and process concepts",
            "A disposable VM with a standard-user test account",
          ];
  const learningObjectives = [
    `Build a clear mental model for ${title}`,
    "Identify the state, decision boundary, required condition, and observable proof",
    "Verify the model with a read-only probe and a meaningful negative control",
  ];
  const contentType = labSlugs.has(slug)
    ? "lab"
    : vulnerabilitySlugs.has(slug)
      ? "vulnerability"
      : "concept";
  const frontmatter = `---
title: ${JSON.stringify(title)}
description: ${JSON.stringify(description)}
locale: "en"
publishDate: 2026-07-28
updatedAt: 2026-07-28
draft: false
featured: false
tags:
${yamlList(
  [
    topicCopy[primary.topic].label,
    primary.track.replaceAll("-", " "),
    "Research Notes",
  ],
  "  ",
)}
author: "Kwpwn"
content_type: ${JSON.stringify(contentType)}
status: "preliminary"
evidence_level: "unverified"
toc: true
wide: false
topic: ${JSON.stringify(primary.topic)}
track: ${JSON.stringify(primary.track)}
seriesOrder: ${primary.order}
topicPlacements:
${placements
  .map(
    ({ topic, track, order }) =>
      `  - topic: ${JSON.stringify(topic)}\n    track: ${JSON.stringify(track)}\n    order: ${order}`,
  )
  .join("\n")}
difficulty: ${JSON.stringify(difficultyFor(placements))}
prerequisites:
${yamlList(prerequisites, "  ")}
learningObjectives:
${yamlList(learningObjectives, "  ")}
labEnvironment: ${JSON.stringify(topicCopy[primary.topic].lab)}
---
`;
  const body = makeBody({
    slug,
    title,
    sourceEntries,
    placements,
    primary,
    mechanics,
  });
  await writeFile(destination, `${frontmatter}\n${body}`, "utf8");
  generated += 1;
}

console.log(`Generated ${generated} curriculum lessons.`);
