import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const refreshGenerated = process.argv.includes("--refresh");
const blogDirectory = path.join(root, "src", "content", "blog");
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
      "https://www.microsoft.com/msrc/security-guidance",
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

function makeBody({
  slug,
  title,
  sourceEntries,
  placements,
  primary,
  mechanics,
}) {
  const copy = topicCopy[primary.topic];
  const mechanismParts = mechanics
    .split(";")
    .map((part) => part.trim().replace(/[.]+$/, ""));
  const inspectionProbe = inspectionProbes[slug];
  if (!inspectionProbe) {
    throw new Error(`Missing topic-specific inspection probe for ${slug}`);
  }
  const concepts = mechanismParts
    .map(
      (part, index) =>
        `${index + 1}. **${["State", "Boundary", "Constraint", "Evidence"][index] ?? "Mechanism"}:** ${part}.`,
    )
    .join("\n");
  const sourceList = sourceEntries
    .map(({ title: sourceTitle, url }) => `- [${sourceTitle}](${url})`)
    .join("\n");
  const references = [
    ...new Set([...sourceEntries.map(({ url }) => url), ...copy.references]),
  ];
  const referenceList = references
    .map((url, index) => `${index + 1}. ${url}`)
    .join("\n");
  const placementSummary = placements
    .map(
      ({ topic, track, order }) =>
        `${topic} lesson ${String(order).padStart(2, "0")} in \`${track}\``,
    )
    .join("; ");

  return `${copy.intro}

The subject here is **${title}**. The goal is not to memorize a named
technique or an undocumented field. The goal is to be able to explain the
mechanism, establish its preconditions, collect version-aware evidence, and
recognize when an apparently similar observation is actually a different
case. In the curriculum this page is placed as ${placementSummary}.

## Concept in one sentence

${mechanismParts[0]}. This definition is deliberately operational: it names
state that can be inspected and avoids treating a product, utility, or
structure name as an explanation.

## Questions this lesson answers

- ${copy.question}
- Which statement is a documented contract, which is a lab observation, and
  which remains an inference?
- What is the smallest safe experiment that distinguishes the leading
  hypothesis from a plausible alternative?
- Which OS build, architecture, policy, identity, and lifecycle conditions
  must accompany the result?

These questions form a reusable reading lens. They also prevent a common
failure mode in security notes: copying a command that produces an interesting
line without explaining why the line matters or what would make it irrelevant.

## System model

The mechanism can be decomposed into four connected claims:

${concepts}

Read those claims from left to right as a state transition, then from right to
left as an evidence plan. If the final effect is claimed, there must be
evidence for the constraint and boundary that made the transition possible.
If a prerequisite cannot be observed, label it unknown. Do not silently
promote it to true.

## Lifecycle and ownership

Every Windows security mechanism has an owner and a lifecycle. Identify the
component that creates the relevant state, the object or record that retains
it, the identity allowed to modify it, the consumer that reads it, and the
event that retires or invalidates it. This is more precise than a flat list of
APIs because APIs are entry points into a state machine, not the state machine
itself.

For **${title}**, build the lifecycle around the four claims above. Mark
asynchronous boundaries explicitly. A service, worker thread, scheduled
callback, provider host, loader, or kernel deferred routine may consume data
long after the originating call returned. That time gap changes both object
lifetime and the telemetry needed to reconstruct causality.

Ownership is equally important. A handle is not the object; a process ID is
not the process object; a filename is not the mapped image; a registry path is
not proof that a specific view was read. Record references and identities at
the boundary where the security decision or state transition actually occurs.

## Trust-boundary map

| Dimension | Record explicitly | Why it changes the result |
| --- | --- | --- |
| Actor | SID, groups, privileges, integrity, process and thread context | Account names hide deny-only groups, filtering, and impersonation |
| Controlled input | Exact object, bytes, value, path, message, or policy | Similar-looking locations may have different owners and consumers |
| Consumer | Image, service or manager, token, bitness, and session | The consumer determines authority and parsing behavior |
| Trigger | Call, boot phase, logon, timer, connection, load, or restart | Writable state without a reachable trigger is not a complete chain |
| Result | New state, access decision, event, mapping, or execution context | The result must be measurable without assuming the conclusion |
| Negative control | One removed prerequisite and the expected changed outcome | It distinguishes causality from coincidence |

This table should be completed before a lab is run. Empty cells are useful:
they expose exactly what research is still required.

## Version and configuration dimensions

Windows internals and security behavior are versioned. Record edition,
architecture, build number, cumulative update, boot security state, relevant
policy source, and whether the observation came from a native or WoW64
process. A blog post, proof of concept, or structure browser may describe a
different build. Treat its offsets, defaults, and reachable paths as
hypotheses until reproduced.

Configuration has provenance. Local policy, domain policy, mobile-device
management, installer state, service configuration, and runtime calls can
produce the same visible value through different authorities. Preserve both
the effective setting and, where available, its policy source. A reliable
write-up should say “observed on build X with policy Y” rather than “Windows
always does Z.”

## Evidence-first workflow

1. **Freeze context.** Record time, build, architecture, current token,
   relevant policy, and specimen or object identity.
2. **State one claim.** Write a falsifiable sentence using the actor, controlled
   input, consumer, trigger, and result.
3. **Collect the least-invasive evidence.** Prefer documented queries, ACL
   inspection, event collection, symbols, and offline parsing.
4. **Run a benign positive control.** Confirm the sensor and interpretation can
   observe a known safe event.
5. **Run a negative control.** Remove one prerequisite or query a clearly
   unaffected object and predict the changed result.
6. **Correlate independent sources.** A configuration record plus runtime
   telemetry is stronger than either alone.
7. **Classify confidence.** Separate fact, observation, inference, and unknown.
8. **Reset and repeat.** Reproduction after snapshot restore detects hidden
   state and timing assumptions.

The workflow intentionally delays high-impact activity. Most incorrect
findings can be rejected through reachability, identity, ACL, build, or policy
evidence without attempting an exploit or executing an unknown sample.

## Safe guided lab

${copy.lab}

Create a case directory outside synchronized folders. Save the baseline
commands and redirect their output to timestamped text files if you need an
audit trail:

\`\`\`powershell
${copy.commands}
\`\`\`

Write the hypothesis before collecting topic-specific evidence:

\`\`\`json
${copy.evidence}
\`\`\`

For this lesson, populate the \`controlled_object\` or \`observation\` fields
with the exact item described in the System model. Then perform two read-only
passes: the first from the intended low-privileged or analysis context, and the
second against a test object you created with a deliberately different
configuration. Do not use a production service, another user's credential
material, a live C2 endpoint, or an unsigned kernel component.

### Topic-specific inspection probe

The following probe is deliberately read-only. Replace placeholders only with
an object, process, file, trace, or VM that belongs to the lab. Some commands
require an elevated debugging console to *inspect* kernel or system state;
elevation for observation does not prove that a standard user could reach the
same state transition.

\`\`\`text
${inspectionProbe}
\`\`\`

Interpret each line through the trust-boundary table. Capture the complete
output, command context, exit status, and time. A command that is unavailable
on a particular edition or build is itself a version note, not permission to
substitute an unrelated conclusion.

Use this compact decision record after each pass:

\`\`\`text
Claim:
Observed fact:
Supporting source:
Alternative explanation:
Negative control:
Result of negative control:
Windows build and policy:
Confidence: confirmed | supported | tentative | rejected
\`\`\`

The lab is complete when the negative control changes the predicted evidence,
not when a tool prints a dramatic label.

## Worked case study

Assume an analyst reports **${title}** after observing only the first visible
artifact. The review team does not accept the label immediately. It reconstructs
the four mechanism claims, identifies the owning component, and asks whether
the observed actor can reach the relevant transition on the recorded build.

The first pass confirms the artifact but leaves consumer identity and trigger
unknown. The team therefore marks the case *tentative*. A second pass captures
runtime telemetry while a benign test object follows the documented path. This
establishes the expected consumer, timing, and result. Finally, the team removes
one prerequisite—permission, policy, input, provider, mapping, or trigger,
depending on the mechanism—and repeats the test. The predicted event or state
transition disappears.

That sequence supports causality. If the result had remained unchanged, the
original model would be rejected or revised. The important lesson is that a
case study is not valuable because it names a famous technique. It is valuable
because another reader can reproduce the claim, observe its limits, and tell
which part of the chain failed.

## Telemetry and detection strategy

Detection should follow invariant state transitions instead of copying one
command line. Build a matrix with one row for each step in the mechanism and
columns for configuration evidence, process or thread evidence, object or
memory evidence, and external collection. Record sensor prerequisites and
retention. A missing row then means “coverage unknown” rather than “activity
did not happen.”

Prefer joined signals: an unusual writer plus a sensitive object; a privileged
consumer plus lower-privileged input; a protection change plus an anomalous
thread start; a provider action plus a repository change; or a network message
plus correlated task execution. Joins reduce dependence on superficial names
that can change while the underlying mechanism remains.

Hardening should break the earliest practical edge in the chain. Remove
unnecessary reachability, narrow object permissions, enforce code or caller
identity, disable unused components, strengthen protocol authentication, and
retain telemetry outside the authority of the component being monitored.
Validate the control with the same positive and negative tests used to
establish the original model.

## Common analytical failures

- Treating a scanner, catalog, debugger extension, or framework label as proof.
- Quoting a structure offset or default without recording the Windows build.
- Confusing a writable object with a privileged consumer that will read it.
- Confusing a process primary token with a thread impersonation token.
- Treating missing telemetry as absence without a sensor-health control.
- Running from an administrator console and attributing the result to a
  standard user.
- Presenting an isolated API call without object lifetime, cleanup, or error
  behavior.
- Reproducing only the positive case and therefore failing to establish
  causality.

These failures are useful review prompts. A strong article makes each one hard
to commit because its evidence ledger exposes the missing link.

## Review checklist

- [ ] I can define the concept without using a product or exploit name.
- [ ] I can name the manager, owner, object, actor, consumer, trigger, and result.
- [ ] I recorded build, architecture, policy, identity, and time.
- [ ] I separated a documented contract from an observation and an inference.
- [ ] I used a benign positive control and a meaningful negative control.
- [ ] I know which sensor gaps could hide the expected transition.
- [ ] I can state at least one configuration where the conclusion no longer holds.
- [ ] My notes contain enough provenance for another reader to reproduce them.

## Source coverage

This local lesson consolidates the following Yunolay source material into a
single mechanism-first document. Consolidation avoids duplicate pages while
preserving every source URL in the reference ledger.

${sourceList}

## References

${referenceList}
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
    if (!refreshGenerated) continue;
  } catch {
    // The lesson does not exist yet.
  }

  const description = `A mechanism-first, version-aware study of ${title}, with trust boundaries, evidence collection, a safe guided lab, telemetry, hardening, and reproducible case analysis.`;
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
    `Explain ${title} as a sequence of state transitions and trust boundaries`,
    "Collect version-aware evidence and distinguish fact, observation, inference, and unknown",
    "Design a safe positive control, negative control, detection plan, and hardening check",
  ];
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
