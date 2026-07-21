import type { HandbookConcept } from "./windows-security-handbook";
import { makeConcept } from "./windows-security-catalog-helpers";

const serviceRights =
  "https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights";

export const lpeConcepts: HandbookConcept[] = [
  makeConcept({
    slug: "service-security",
    title: "Service security model",
    group: "lpe-services",
    level: "Foundation",
    summary:
      "Windows services combine two securable layers—the SCM database and each service object—with registry configuration, executable files, DLLs, accounts, privileges, triggers, and IPC endpoints.",
    model:
      "Audit rights as a graph: caller → SCM handle → service handle → configuration → referenced files/registry → service token → trigger. A weakness at any edge may be harmless unless the complete path reaches a stronger action.",
    enables: [
      "Interpret service-specific access masks",
      "Distinguish control-plane and filesystem weaknesses",
      "Build evidence-backed service LPE chains",
    ],
    checks: [
      "Which SCM and service rights are actually granted?",
      "Which account and privileges does the service receive?",
      "Can the service be started or otherwise triggered?",
      "Who controls every referenced path, DLL, registry value, and IPC endpoint?",
    ],
    apis: [
      {
        name: "OpenSCManagerW",
        purpose: "Open the SCM database.",
        flags: "SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE",
      },
      {
        name: "OpenServiceW",
        purpose: "Open one service with requested service-specific rights.",
      },
      {
        name: "QueryServiceConfigW",
        purpose: "Read account, start type, and binary path.",
      },
      {
        name: "QueryServiceObjectSecurity",
        purpose: "Read the service object's security descriptor.",
      },
    ],
    sources: [
      {
        title: "Service security and access rights",
        href: serviceRights,
        kind: "primary",
      },
    ],
    related: [
      "weak-service-dacl",
      "service-binary-path",
      "service-registry-permissions",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "weak-service-dacl",
    title: "Weak service DACL",
    group: "lpe-services",
    summary:
      "A service object's DACL grants a weaker principal a service-specific right that can alter configuration, security, lifecycle, or privileged control behavior.",
    model:
      "Decode the exact mask. SERVICE_QUERY_STATUS is normal and low risk; SERVICE_CHANGE_CONFIG, WRITE_DAC, WRITE_OWNER, SERVICE_START, SERVICE_STOP, or a vendor-defined control may compose into real authority.",
    enables: [
      "Change binary path, account, or start configuration",
      "Take ownership or rewrite the service DACL",
      "Trigger or control a privileged service",
    ],
    checks: [
      "Which ACE grants which service-specific bits?",
      "Can the service be stopped and restarted without separate admin rights?",
      "Does configuration change preserve or reset credentials?",
      "Can a custom control reach a sensitive handler?",
    ],
    steps: [
      "Open the service with READ_CONTROL and query its DACL without changing it.",
      "Map every granted access bit to the documented service-specific operation.",
      "Test the weakest meaningful operation in a disposable lab and record whether a separate start/trigger right is required.",
      "Prove the final action runs under the service account and preserve the original descriptor/configuration for restoration.",
    ],
    sources: [
      {
        title: "Service security and access rights",
        href: serviceRights,
        kind: "primary",
      },
    ],
    related: [
      "security-descriptors",
      "service-security",
      "acl-misconfiguration",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "service-binary-path",
    title: "Writable service binary or binary path",
    group: "lpe-services",
    summary:
      "A weaker principal can replace the configured executable, modify its contents, or change the service configuration to point at controlled code that a stronger service account later starts.",
    model:
      "Separate three cases: writable executable file, writable parent enabling replacement, and SERVICE_CHANGE_CONFIG enabling a new path. Each has different owner, DACL, sharing, and trigger requirements.",
    enables: [
      "Execute controlled code as the service account",
      "Persist through a privileged service start",
      "Convert service configuration rights into a token boundary crossing",
    ],
    checks: [
      "Is the executable itself writable or only a parent directory?",
      "Does replacement preserve required signing or format?",
      "Can the attacker start/restart the service?",
      "Which account, privileges, integrity, and service SID apply?",
    ],
    sources: [
      {
        title: "Changing a service configuration",
        href: "https://learn.microsoft.com/en-us/windows/win32/services/changing-a-service-s-configuration",
        kind: "primary",
      },
    ],
    related: ["weak-service-dacl", "arbitrary-file-write", "service-security"],
  }),
  makeConcept({
    slug: "unquoted-service-path",
    title: "Unquoted service path",
    group: "lpe-services",
    summary:
      "A service command line containing spaces is not quoted, allowing process creation to test shorter executable-name candidates before the intended binary.",
    model:
      "The unquoted string is only one condition. Exploitability requires a candidate prefix path where the attacker can create the exact executable and a service start under a stronger principal.",
    enables: [
      "Redirect service process creation",
      "Execute an earlier candidate binary",
      "Demonstrate path parsing as an identity boundary",
    ],
    checks: [
      "What exact candidates does CreateProcess test?",
      "Can the attacker create a file at any candidate path?",
      "Is the executable path truly unquoted rather than only displayed without quotes?",
      "Can the service be triggered?",
    ],
    sources: [
      {
        title: "CreateProcessW parameter parsing",
        href: "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw",
        kind: "primary",
      },
    ],
    related: [
      "service-binary-path",
      "path-canonicalization",
      "arbitrary-file-create",
    ],
  }),
  makeConcept({
    slug: "service-dll-loading",
    title: "Writable service DLL and plugin loading",
    group: "lpe-services",
    summary:
      "A service or shared host loads a DLL, plugin, provider, extension, or handler from a path or registration value influenced by a weaker principal.",
    model:
      "Recover the loader call, module name, search flags, working directory, registry source, architecture, signature policy, and load trigger. Missing DLL, replacement, proxying, and search-order cases are distinct.",
    enables: [
      "Execute inside a privileged service",
      "Persist through a plugin/provider mechanism",
      "Convert registry or file write into SYSTEM code loading",
    ],
    checks: [
      "Is the load path absolute?",
      "Which directories are searched and writable?",
      "Is the module absent, replaceable, or configured through registry?",
      "Does the service enforce publisher, hash, or CI policy?",
    ],
    sources: [
      {
        title: "Dynamic-link library security",
        href: "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security",
        kind: "primary",
      },
    ],
    related: [
      "dll-hijacking",
      "service-registry-permissions",
      "arbitrary-file-write",
    ],
  }),
  makeConcept({
    slug: "service-registry-permissions",
    title: "Weak service registry permissions",
    group: "lpe-services",
    summary:
      "A service object's DACL may be secure while its Services registry key, Parameters subkey, policy values, DLL path, or vendor configuration remains writable by ordinary users.",
    model:
      "Registry permission and service permission are independent. Identify the exact value, type, WOW64 view, consumer, caching behavior, service restart requirement, and privileged side effect.",
    enables: [
      "Redirect DLL or executable configuration",
      "Change gate or policy state",
      "Influence privileged service behavior",
    ],
    checks: [
      "Which key and value are writable?",
      "Does the service read it at start, per request, or only install time?",
      "Is the value path canonicalized and signed?",
      "Which registry view and inherited DACL apply?",
    ],
    sources: [
      {
        title: "Registry key security and access rights",
        href: "https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights",
        kind: "primary",
      },
    ],
    related: [
      "registry-based-primitives",
      "service-dll-loading",
      "service-security",
    ],
  }),
  makeConcept({
    slug: "service-failure-actions",
    title: "Service failure actions and recovery",
    group: "lpe-services",
    summary:
      "SCM recovery policy can restart a service, reboot, or run a configured command after failure, creating a privileged execution path if configuration rights or referenced files are weak.",
    model:
      "Failure actions are a stateful trigger. Audit who can set them, what account executes the command, the reset period, which failures count, path quoting, and whether failure can be induced safely.",
    enables: [
      "Trigger configured recovery commands",
      "Restart a privileged service after controlled failure",
      "Persist through recovery policy",
    ],
    checks: [
      "Who has SERVICE_CHANGE_CONFIG?",
      "Is a command action configured and safely quoted?",
      "Does it run as the service account or SCM context?",
      "Can failure be triggered without destructive system impact?",
    ],
    sources: [
      {
        title: "SERVICE_FAILURE_ACTIONS",
        href: "https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw",
        kind: "primary",
      },
    ],
    related: [
      "weak-service-dacl",
      "service-control-abuse",
      "service-binary-path",
    ],
  }),
  makeConcept({
    slug: "service-control-abuse",
    title: "Service controls and custom handlers",
    group: "lpe-services",
    summary:
      "Service control rights allow lifecycle changes or vendor-defined control codes that may invoke sensitive behavior in a SYSTEM service.",
    model:
      "Map the granted SERVICE_* right to accepted control codes and the service's HandlerEx implementation. A custom control is an RPC-reachable method and needs its own authorization and input analysis.",
    enables: [
      "Start, stop, pause, or continue a service",
      "Reach vendor-defined privileged operations",
      "Trigger reload, repair, update, or cleanup paths",
    ],
    checks: [
      "Which controls are accepted in the current state?",
      "What rights does SCM require for each control?",
      "Does the service perform a second caller authorization check?",
      "Can control data or global configuration influence file or process operations?",
    ],
    sources: [
      {
        title: "Service control handler function",
        href: "https://learn.microsoft.com/en-us/windows/win32/services/service-control-handler-function",
        kind: "primary",
      },
    ],
    related: [
      "weak-service-dacl",
      "rpc-services",
      "privileged-file-operations",
    ],
  }),
  makeConcept({
    slug: "weak-device-dacl",
    title: "Weak device-object DACL",
    group: "lpe-services",
    summary:
      "A named device object grants a weaker principal a handle with rights sufficient to reach privileged IOCTLs or other driver operations.",
    model:
      "Device exposure is the first layer, not the whole finding. Combine device SDDL, FILE_DEVICE_SECURE_OPEN, desired access, IOCTL access bits, create policy, gate state, and operation-level validation.",
    enables: [
      "Reach sensitive vendor IOCTLs",
      "Open a device from standard-user context",
      "Turn a designed hardware backend into an LPE primitive",
    ],
    checks: [
      "Which SID can open the device and with what access?",
      "Are names below the device protected by secure-open behavior?",
      "Which sensitive IOCTLs use FILE_ANY_ACCESS?",
      "Is a broker service or per-request token check intended?",
    ],
    sources: [
      {
        title: "Applying security descriptors on the device object",
        href: "https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/applying-security-descriptors-on-the-device-object",
        kind: "primary",
      },
    ],
    related: [
      "security-descriptors",
      "ioctl-handlers",
      "driver-gates-and-handshakes",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "token-impersonation",
    title: "Token impersonation",
    group: "lpe-services",
    summary:
      "A thread adopts a client's impersonation token so access checks and resource operations execute as that security context until the thread reverts.",
    model:
      "Track token type, impersonation level, origin, effective-only state, privileges, session, and reversion. Identification is not delegation; an impersonation token is not automatically a primary token for process creation.",
    enables: [
      "Access resources as a privileged client",
      "Duplicate a token when rights allow",
      "Bridge IPC identity into a privileged operation",
    ],
    checks: [
      "Which server thread impersonates which authenticated client?",
      "What impersonation level was negotiated?",
      "Can the token be duplicated as primary?",
      "Is RevertToSelf guaranteed on errors, exceptions, and asynchronous work?",
    ],
    sources: [
      {
        title: "Client impersonation",
        href: "https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation",
        kind: "primary",
      },
    ],
    related: [
      "access-tokens",
      "named-pipe-impersonation",
      "seimpersonate-privilege",
    ],
  }),
  makeConcept({
    slug: "named-pipe-impersonation",
    title: "Named-pipe impersonation",
    group: "lpe-services",
    summary:
      "A pipe server impersonates a connected client; an escalation chain exists when a privileged client can be induced to connect and the server is allowed to impersonate at a useful level.",
    model:
      "The primitive requires endpoint control, a privileged client, coercion or expected connection, successful message flow, sufficient impersonation level, and a token-use path. Pipe creation alone is not SYSTEM.",
    enables: [
      "Acquire a privileged impersonation token",
      "Duplicate a primary token when allowed",
      "Perform resource operations as the client",
    ],
    checks: [
      "Who owns the pipe name and first instance?",
      "Why does the privileged client connect?",
      "Has the client sent data before impersonation?",
      "Which privileges and token rights are present on the server?",
    ],
    sources: [
      {
        title: "ImpersonateNamedPipeClient",
        href: "https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient",
        kind: "primary",
      },
    ],
    related: [
      "token-impersonation",
      "seimpersonate-privilege",
      "named-pipe-surface",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "seimpersonate-privilege",
    title: "SeImpersonatePrivilege",
    group: "lpe-services",
    summary:
      "SeImpersonatePrivilege permits a process to impersonate clients after authentication under documented conditions, making privileged-client coercion valuable to many service-account LPE chains.",
    model:
      "The privilege is an enabling condition, not the exploit. The chain still needs an IPC server controlled by the attacker, a stronger client, a connection/authentication event, a usable impersonation level, and a final token operation.",
    enables: [
      "Impersonate authenticated local clients",
      "Use named-pipe, RPC, COM, or other server-side token flows",
      "Compose service-account rights into SYSTEM",
    ],
    checks: [
      "Is the privilege present and enabled?",
      "Which privileged client can be induced to authenticate?",
      "Does the protocol deliver a usable impersonation level?",
      "Can the resulting token perform the intended final action?",
    ],
    sources: [
      {
        title: "Impersonate a client after authentication",
        href: "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn221967(v=ws.11)",
        kind: "primary",
      },
    ],
    related: [
      "named-pipe-impersonation",
      "token-impersonation",
      "rpc-services",
    ],
  }),
  makeConcept({
    slug: "handle-acquisition",
    title: "Privileged handle acquisition",
    group: "lpe-services",
    summary:
      "A weaker process obtains, inherits, receives, leaks, or duplicates a handle to a process, thread, token, section, service, job, device, or file with unintended rights.",
    model:
      "Record object type, owning process, granted mask, inheritance/duplication path, protection level, and the smallest operation enabled. A numeric handle value without ownership and rights is not a capability.",
    enables: [
      "Duplicate tokens or other handles",
      "Read/write process memory or create threads",
      "Control services, devices, files, or sections",
    ],
    checks: [
      "Who owns the source handle?",
      "What exact granted rights are present?",
      "Can it be inherited or duplicated across the boundary?",
      "Does PPL, signer policy, or session isolation still block use?",
    ],
    sources: [
      {
        title: "DuplicateHandle",
        href: "https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle",
        kind: "primary",
      },
    ],
    related: [
      "handles-and-access-masks",
      "process-thread-token-surface",
      "token-impersonation",
    ],
  }),
  makeConcept({
    slug: "com-hijacking",
    title: "COM hijacking",
    group: "lpe-services",
    summary:
      "A weaker principal controls COM registration or a referenced server path resolved by a stronger client, redirecting class activation to attacker-controlled code.",
    model:
      "Map CLSID, AppID, TreatAs, ProgID, InprocServer32/LocalServer32, proxy/stub, per-user versus machine registration, 32/64-bit view, activation principal, and load trigger.",
    enables: [
      "Execute in a privileged COM client or server context",
      "Persist through class activation",
      "Redirect missing or writable class registration",
    ],
    checks: [
      "Does the privileged client consult per-user registration?",
      "Is activation in-process or out-of-process?",
      "Which registry view wins?",
      "Is the target a real elevation boundary rather than only same-user persistence?",
    ],
    sources: [
      {
        title: "Registering COM servers",
        href: "https://learn.microsoft.com/en-us/windows/win32/com/registering-com-servers",
        kind: "primary",
      },
    ],
    related: ["com-activation", "registry-based-primitives", "dll-hijacking"],
    featured: true,
  }),
  makeConcept({
    slug: "dll-hijacking",
    title: "DLL search-order hijacking",
    group: "lpe-services",
    summary:
      "A stronger process loads a DLL by an insufficiently constrained name and the loader selects attacker-controlled content earlier than the intended module.",
    model:
      "Classify the exact case: missing/phantom DLL, search-order planting, writable replacement, side-loading, proxying, or explicit relative path. Then recover the loader flags and effective search path.",
    enables: [
      "Execute code in a privileged process",
      "Persist through repeated module load",
      "Convert file creation/write into execution",
    ],
    checks: [
      "Which API and LOAD_LIBRARY_* flags are used?",
      "Is Safe DLL Search Mode or SetDefaultDllDirectories active?",
      "Which candidate directory is writable?",
      "Does architecture, signature, KnownDLLs, or packaged-app behavior block the load?",
    ],
    sources: [
      {
        title: "Dynamic-link library search order",
        href: "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order",
        kind: "primary",
      },
    ],
    related: [
      "service-dll-loading",
      "arbitrary-file-create",
      "path-canonicalization",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "scheduled-task-abuse",
    title: "Scheduled-task abuse",
    group: "lpe-services",
    summary:
      "A weaker principal can modify a task definition, action, COM handler, working directory, executable, trigger, credential, or backing file used by a more privileged task principal.",
    model:
      "Audit task object security and every referenced resource. Principal/run level, logon type, action type, trigger availability, folder DACL, XML definition, and writable payload path all matter.",
    enables: [
      "Execute on a privileged task trigger",
      "Persist through time/event/logon triggers",
      "Redirect a COM handler or executable action",
    ],
    checks: [
      "Who can read, modify, or run the task?",
      "Which principal and logon type execute it?",
      "Are action paths absolute and protected?",
      "Can the trigger be invoked by the attacker?",
    ],
    sources: [
      {
        title: "Task Scheduler security contexts",
        href: "https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks",
        kind: "primary",
      },
    ],
    related: ["security-descriptors", "com-hijacking", "arbitrary-file-write"],
  }),
  makeConcept({
    slug: "installer-rollback",
    title: "Installer repair and rollback conversion",
    group: "lpe-services",
    summary:
      "Maintenance or rollback state converts file deletion, movement, staging, or metadata control into creation or replacement of files by Windows Installer or another privileged repair engine.",
    model:
      "The initial primitive and final write are separate. Map the transaction, rollback script/state, backup location, owner/DACL, repair trigger, product policy, and the final privileged consumer.",
    enables: [
      "Convert arbitrary delete into privileged file creation",
      "Restore controlled bytes into a protected location",
      "Exploit repair as a confused deputy",
    ],
    checks: [
      "Which rollback or repair artifacts are attacker-influenced?",
      "Who creates the restored file and with which DACL?",
      "Can the transaction be triggered reliably?",
      "Which final sink turns the restored file into authority?",
    ],
    sources: [
      {
        title: "Abusing arbitrary file deletes to escalate privilege",
        href: "https://www.thezdi.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks",
        kind: "case study",
      },
    ],
    related: [
      "arbitrary-file-delete",
      "installer-updater-surface",
      "privileged-file-operations",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "privileged-file-operations",
    title: "Privileged filesystem deputy",
    group: "lpe-services",
    summary:
      "A service, driver, installer, scanner, backup tool, or updater performs create, copy, move, delete, chmod, extract, or restore operations with stronger filesystem authority on attacker-influenced names or objects.",
    model:
      "Write the chain as caller input → path construction → validation → opened handles → privileged operation → owner/DACL of result → final consumer. Every re-resolution is a substitution opportunity.",
    enables: [
      "Arbitrary file/directory capabilities",
      "Cross-DACL modification or disclosure",
      "Non-memory-corruption LPE through a trusted consumer",
    ],
    checks: [
      "Which path components are attacker-controlled?",
      "Are final objects opened relative to a validated parent?",
      "Are reparses and links checked after the final open?",
      "Who owns and can modify the resulting object?",
    ],
    sources: [
      {
        title: "Naming files, paths, and namespaces",
        href: "https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file",
        kind: "primary",
      },
    ],
    related: [
      "filesystem-namespace-surface",
      "oplock-assisted-race",
      "arbitrary-file-write",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "rpc-com-confused-deputy",
    title: "RPC and COM confused deputy",
    group: "lpe-services",
    summary:
      "A privileged server accepts a request from a weaker caller and accesses a resource or performs an operation using server authority when it should impersonate or authorize the client.",
    model:
      "For each method, write subject, requested action, target object, intended authorization, actual token at the sensitive call, and whether client-controlled handles or paths are revalidated.",
    enables: [
      "Privileged file, registry, process, or service operations",
      "Cross-user data access",
      "Authentication coercion or token misuse",
    ],
    checks: [
      "Does the server impersonate before opening the resource?",
      "Is method-level authorization performed after binding?",
      "Can context handles cross clients?",
      "Does asynchronous work accidentally run after reversion under the server token?",
    ],
    sources: [
      {
        title: "Impersonation and cloaking",
        href: "https://learn.microsoft.com/en-us/windows/win32/com/impersonation-and-cloaking",
        kind: "primary",
      },
    ],
    related: ["rpc-services", "com-activation", "token-impersonation"],
  }),
  makeConcept({
    slug: "registry-autorun-and-provider-loading",
    title: "Registry-controlled privileged loading",
    group: "lpe-services",
    summary:
      "A privileged process resolves an autorun, provider, handler, extension, plugin, command, or module path from a registry value writable by a weaker principal.",
    model:
      "Registry control is only the first edge. Record hive/view, value type, environment expansion, path parsing, consumer identity, caching, signature policy, and trigger.",
    enables: [
      "Redirect privileged code loading",
      "Persist through provider registration",
      "Influence command or module selection",
    ],
    checks: [
      "Which key and view does the consumer read?",
      "Is the value or referenced parent path writable?",
      "Does the consumer run at a stronger integrity or account?",
      "Is the value read at every trigger or cached at startup?",
    ],
    sources: [
      {
        title: "Registry key security and access rights",
        href: "https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights",
        kind: "primary",
      },
    ],
    related: ["registry-based-primitives", "dll-hijacking", "com-hijacking"],
  }),
  makeConcept({
    slug: "uac-boundary-model",
    title: "UAC and elevation semantics",
    group: "lpe-services",
    level: "Foundation",
    summary:
      "User Account Control separates filtered and elevated administrator tokens and mediates consent/elevation, but Microsoft does not define the default same-user UAC prompt as a hard security boundary.",
    model:
      "Distinguish standard user → admin/SYSTEM LPE from filtered-admin → elevated-admin UAC behavior. Record token membership, integrity, elevation type, consent policy, auto-elevation, and the final protected resource.",
    enables: [
      "Classify impact accurately",
      "Avoid overstating UAC bypasses as standard-user LPE",
      "Understand split-token and integrity behavior",
    ],
    checks: [
      "Does the chain begin with a standard user or a split-token administrator?",
      "Which consent policy applies?",
      "Is the target auto-elevated and why?",
      "What stronger token or object access is ultimately obtained?",
    ],
    sources: [
      {
        title: "How User Account Control works",
        href: "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works",
        kind: "primary",
      },
    ],
    related: ["access-tokens", "com-hijacking", "authorization-bypass"],
  }),
];
