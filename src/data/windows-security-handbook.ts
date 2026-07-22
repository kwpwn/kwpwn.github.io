import { primitiveConcepts } from "./windows-security-primitives";
import { vulnerabilityClassConcepts } from "./windows-security-vulnerability-classes";
import { attackSurfaceConcepts } from "./windows-security-attack-surfaces";
import { driverTypeConcepts } from "./windows-security-driver-types";
import { lpeConcepts } from "./windows-security-lpe";
import { mitigationConcepts } from "./windows-security-mitigations";
import { workflowConcepts } from "./windows-security-workflow";

export type HandbookGroupId =
  | "foundations"
  | "primitives"
  | "vulnerability-classes"
  | "attack-surfaces"
  | "driver-types"
  | "lpe-services"
  | "mitigations"
  | "research-workflow";

export interface HandbookGroup {
  id: HandbookGroupId;
  title: string;
  shortTitle: string;
  description: string;
  question: string;
  order: number;
}

export interface ConceptApi {
  name: string;
  purpose: string;
  flags?: string;
  href?: string;
}

export interface ConceptSource {
  title: string;
  href: string;
  kind: "primary" | "case study" | "reference";
}

export interface ConceptDemo {
  title: string;
  language: string;
  description: string;
  code: string;
}

export interface HandbookConcept {
  slug: string;
  title: string;
  group: HandbookGroupId;
  level: "Foundation" | "Intermediate" | "Advanced";
  summary: string;
  mentalModel: string;
  whyItMatters: string;
  enables: string[];
  mechanics: string[];
  questions: string[];
  apis?: ConceptApi[];
  demo?: ConceptDemo;
  sources: ConceptSource[];
  related: string[];
  aliases?: string[];
  featured?: boolean;
}

export const handbookGroups: HandbookGroup[] = [
  {
    id: "foundations",
    title: "Windows foundations",
    shortTitle: "Foundations",
    description:
      "The object, identity, memory, and I/O models that make every later security decision understandable.",
    question: "Which Windows contract is supposed to hold?",
    order: 1,
  },
  {
    id: "primitives",
    title: "Primitives and capabilities",
    shortTitle: "Primitives",
    description:
      "What control a bug actually gives: read, write, redirect, create, delete, impersonate, map, or invoke.",
    question: "What can the attacker do, and under which constraints?",
    order: 2,
  },
  {
    id: "vulnerability-classes",
    title: "Vulnerability classes",
    shortTitle: "Vulnerability classes",
    description:
      "The violated invariants behind memory corruption, authorization mistakes, races, path confusion, and protocol bugs.",
    question: "Why did the trusted component make an unsafe decision?",
    order: 3,
  },
  {
    id: "attack-surfaces",
    title: "Attack surfaces",
    shortTitle: "Attack surfaces",
    description:
      "The concrete interfaces where less-trusted input crosses into a privileged component.",
    question: "Where does attacker-controlled state enter privileged code?",
    order: 4,
  },
  {
    id: "driver-types",
    title: "Driver and subsystem families",
    shortTitle: "Driver types",
    description:
      "A map of what each driver family controls, how it is reached, and which failure modes deserve attention.",
    question: "What privileged resource does this component mediate?",
    order: 5,
  },
  {
    id: "lpe-services",
    title: "Local privilege escalation",
    shortTitle: "LPE and services",
    description:
      "Service, token, IPC, COM, loader, installer, filesystem, and object-permission chains that can end in SYSTEM.",
    question: "Which stronger principal performs the final sensitive action?",
    order: 6,
  },
  {
    id: "mitigations",
    title: "Mitigations and boundaries",
    shortTitle: "Mitigations",
    description:
      "Controls that change target selection, execution strategy, observability, or whether a primitive composes at all.",
    question: "Which exploit assumption is invalidated on this exact build?",
    order: 7,
  },
  {
    id: "research-workflow",
    title: "Research workflow",
    shortTitle: "Workflow",
    description:
      "A repeatable path through mapping, reversing, debugging, fuzzing, patch diffing, reproduction, and evidence.",
    question: "What evidence would prove or disprove the current hypothesis?",
    order: 8,
  },
];

const microsoftDriverDocs =
  "https://learn.microsoft.com/en-us/windows-hardware/drivers/";
const kernelSight = "https://splintersfury.github.io/KernelSight/";
const concepts: HandbookConcept[] = [
  {
    slug: "trust-boundaries",
    title: "Windows trust boundaries",
    group: "foundations",
    level: "Foundation",
    summary:
      "A trust boundary exists wherever data or authority crosses from a weaker principal into code, an object, or a service that can act with more privilege.",
    mentalModel:
      "Draw five boxes before reading code: caller, transport, privileged receiver, protected resource, and final security decision. A vulnerability is usually a missing or incorrect check on one arrow between those boxes.",
    whyItMatters:
      "Starting with the boundary prevents category mistakes. A crash in a SYSTEM service is not automatically LPE, an admin-only device is not a standard-user surface, and a signed driver is not automatically a secure driver.",
    enables: [
      "Separate reachability from exploitability",
      "Name the principal that supplies each input",
      "Locate the operation that changes authority",
    ],
    mechanics: [
      "Identify the least-privileged caller that can reach the interface.",
      "Record every identity transition: client token, impersonation token, service account, requestor mode, and session.",
      "Find the exact access check or validation that is expected to protect the sensitive action.",
      "Prove the impact with the final object, right, or operation obtained—not only with a crash or unexpected return value.",
    ],
    questions: [
      "Can an ordinary user create the required handle or endpoint?",
      "Does the privileged component impersonate the client before touching the resource?",
      "Is authorization checked against the caller, a configured identity, or only a packet marker?",
      "Which assumption changes across sessions, integrity levels, AppContainers, or service SIDs?",
    ],
    sources: [
      {
        title: "Windows security model for driver developers",
        href: `${microsoftDriverDocs}driversecurity/windows-security-model`,
        kind: "primary",
      },
      { title: "KernelSight overview", href: kernelSight, kind: "reference" },
    ],
    related: [
      "access-tokens",
      "security-descriptors",
      "handles-and-access-masks",
    ],
    featured: true,
  },
  {
    slug: "object-manager-namespaces",
    title: "Object Manager and namespaces",
    group: "foundations",
    level: "Foundation",
    summary:
      "The Windows Object Manager gives named kernel objects—devices, directories, symbolic links, sections, events, and more—a hierarchical namespace with security and lifetime rules distinct from NTFS.",
    mentalModel:
      "Treat an NT path as a sequence of object lookups. Each path component can enter a different namespace, resolve a symbolic link, and be checked against a different security descriptor.",
    whyItMatters:
      "Many non-memory-corruption chains rely on confusing an Object Manager symbolic link with an NTFS reparse point, creating an object in a per-session directory, or inducing privileged code to resolve a name in an attacker-influenced namespace.",
    enables: [
      "Reason about device paths such as \\.\\Name and \\Device\\Name",
      "Understand namespace squatting and symbolic-link redirection",
      "Track object lifetime independently from handle lifetime",
    ],
    mechanics: [
      "Win32 paths are translated into NT object paths before the I/O manager resolves a device and optional filesystem tail.",
      "Object directories contain named objects and can carry DACLs; sessions and AppContainers can introduce private namespace views.",
      "Object Manager symbolic links redirect NT namespace lookup, while NTFS junctions and reparse points are interpreted by filesystem drivers.",
      "A safe design opens the intended parent and validates the identity of the resulting object instead of trusting a mutable string path.",
    ],
    questions: [
      "Which object directory contains the name?",
      "Who can create siblings or symbolic links there?",
      "Does the path cross from the Object Manager into a filesystem volume?",
      "Is the privileged operation bound to an already-open handle or does it resolve the path again?",
    ],
    apis: [
      {
        name: "NtOpenDirectoryObject",
        purpose: "Open an Object Manager directory.",
      },
      {
        name: "NtQueryDirectoryObject",
        purpose: "Enumerate named kernel objects.",
      },
      {
        name: "NtCreateSymbolicLinkObject",
        purpose: "Create an NT object symbolic link.",
      },
      { name: "QueryDosDeviceW", purpose: "Inspect DOS-device name mappings." },
    ],
    sources: [
      {
        title: "Object directories",
        href: "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-directories",
        kind: "primary",
      },
      {
        title:
          "Windows exploitation tricks: exploiting arbitrary object directory creation",
        href: "https://projectzero.google/2018/08/windows-exploitation-tricks-exploiting.html",
        kind: "case study",
      },
    ],
    related: [
      "object-manager-symbolic-links",
      "reparse-points",
      "arbitrary-directory-create",
    ],
    featured: true,
  },
  {
    slug: "access-tokens",
    title: "Access tokens and identity",
    group: "foundations",
    level: "Foundation",
    summary:
      "An access token is the kernel representation of a security context: user and group SIDs, privileges, integrity level, restrictions, elevation state, and other policy used during authorization.",
    mentalModel:
      "A process normally carries a primary token; a thread may temporarily carry an impersonation token. Access checks compare the effective token with an object's security descriptor and the requested access mask.",
    whyItMatters:
      "Token theft, impersonation, privilege enabling, primary-token replacement, and direct token-field corruption are different capabilities with different prerequisites and detection artifacts.",
    enables: [
      "Explain why a handle open succeeds or fails",
      "Distinguish primary and impersonation tokens",
      "Measure privilege escalation without relying on account names",
    ],
    mechanics: [
      "The caller requests an access mask while opening a securable object.",
      "Windows selects the effective primary or impersonation token for the check.",
      "The security reference monitor evaluates deny/allow ACEs, mandatory integrity, privileges, and restrictions.",
      "The granted access mask is stored on the resulting handle and is normally not recalculated for every use.",
    ],
    questions: [
      "Is the token primary or impersonation, and at which impersonation level?",
      "Which privileges are present versus enabled?",
      "What integrity level, session, AppContainer, or restriction applies?",
      "Does the final operation require a new primary token or only temporary impersonation?",
    ],
    apis: [
      {
        name: "OpenProcessToken",
        purpose: "Open a process primary token.",
        flags: "TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_ASSIGN_PRIMARY",
      },
      {
        name: "OpenThreadToken",
        purpose: "Open a thread impersonation token.",
        flags: "OpenAsSelf changes which context performs the open",
      },
      {
        name: "DuplicateTokenEx",
        purpose: "Create a primary or impersonation token.",
        flags: "TokenPrimary, TokenImpersonation",
      },
      {
        name: "GetTokenInformation",
        purpose: "Query SIDs, privileges, integrity, type, and elevation.",
      },
    ],
    demo: {
      title: "Inspect the current token without changing it",
      language: "powershell",
      description:
        "This read-only sample exposes the user, groups, and privilege state that should be recorded before evaluating an LPE chain.",
      code: `$snapshot = [ordered]@{\n  TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')\n  Build = [System.Environment]::OSVersion.VersionString\n  User = whoami.exe /user\n  Groups = whoami.exe /groups\n  Privileges = whoami.exe /priv\n  CompleteTokenView = whoami.exe /all\n}\n\n$snapshot | ConvertTo-Json -Depth 4\n\n# Repeat from the comparison process or impersonating thread. Record token type,\n# impersonation level, integrity, elevation, enabled privileges, and restricted SIDs.`,
    },
    sources: [
      {
        title: "Access tokens",
        href: "https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens",
        kind: "primary",
      },
    ],
    related: [
      "security-descriptors",
      "token-impersonation",
      "token-manipulation",
    ],
    featured: true,
  },
  {
    slug: "security-descriptors",
    title: "Security descriptors, ACLs, and DACLs",
    group: "foundations",
    level: "Foundation",
    summary:
      "A security descriptor binds an owner, primary group, DACL, SACL, and control flags to a securable object; the DACL determines which requested operations are allowed or denied.",
    mentalModel:
      "An ACL is a list; a DACL is the access-control list inside a security descriptor. Each ACE names a SID, an allow/deny type, inheritance behavior, and an access mask. The meaning of each bit depends on the object type.",
    whyItMatters:
      "Saying 'weak ACL' is incomplete. A useful finding names the object, ACE, principal, granted right, reachable privileged action, inheritance path, and whether the access is expected by design.",
    enables: [
      "Read SDDL and object-specific access masks",
      "Distinguish a broad exposure from an exploitable permission",
      "Explain owner, inheritance, null-DACL, and empty-DACL behavior",
    ],
    mechanics: [
      "The client asks for specific desired access while opening an object.",
      "Generic rights are mapped to object-specific rights before the DACL is evaluated.",
      "Deny and allow ACE ordering, token SIDs, restricted SIDs, privileges, and mandatory labels influence the result.",
      "The granted access is attached to the handle; server code may still need method-level authorization afterward.",
    ],
    questions: [
      "Is the DACL absent, null, empty, inherited, or explicitly protected?",
      "Which exact object-specific rights are granted to which SID?",
      "Does WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, or a narrower right create the real escalation path?",
      "Is there a second authorization decision after the handle is opened?",
    ],
    apis: [
      {
        name: "GetSecurityInfo",
        purpose: "Read a handle-based security descriptor.",
        flags: "OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION",
      },
      {
        name: "GetNamedSecurityInfoW",
        purpose: "Read security from a named object.",
      },
      {
        name: "AccessCheck",
        purpose: "Evaluate a descriptor against an impersonation token.",
      },
      {
        name: "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        purpose: "Render a descriptor as SDDL.",
      },
    ],
    demo: {
      title: "Read service SDDL safely",
      language: "powershell",
      description:
        "This does not modify the service. Read the ACEs, then decode the service-specific rights instead of treating every non-default SDDL string as a vulnerability.",
      code: `$serviceName = 'Spooler'\n$serviceKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$serviceName"\n\nsc.exe sdshow $serviceName\nGet-Acl -LiteralPath $serviceKey | Format-List Owner, Group, Sddl, AccessToString\nGet-CimInstance Win32_Service -Filter "Name='$serviceName'" |\n  Select-Object Name, StartName, State, StartMode, PathName\n\n# Decode every ACE into service-specific rights such as SERVICE_START,\n# SERVICE_STOP, SERVICE_CHANGE_CONFIG, WRITE_DAC, and WRITE_OWNER. Compare an\n# allowed request with a denied request; this snippet does not change the DACL.`,
    },
    sources: [
      {
        title: "Security descriptors",
        href: "https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors",
        kind: "primary",
      },
      {
        title: "Service security and access rights",
        href: "https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights",
        kind: "primary",
      },
    ],
    related: [
      "access-checks",
      "weak-service-dacl",
      "acl-security-descriptor-manipulation",
    ],
    featured: true,
  },
  {
    slug: "access-checks",
    title: "Access checks",
    group: "foundations",
    level: "Intermediate",
    summary:
      "An access check answers whether a particular security context may obtain a particular set of rights to a securable object at a specific moment.",
    mentalModel:
      "Authorization is a function of token + security descriptor + requested mask + object-type mapping + access mode. Change any operand and the decision can change.",
    whyItMatters:
      "Many driver and service bugs are not missing DACLs; they are checks performed with KernelMode, checks against the wrong token, generic-mask mistakes, cached authorization attached to the wrong object, or no method-level check after a broad open.",
    enables: [
      "Audit authorization at the correct layer",
      "Spot RequestorMode confusion",
      "Differentiate open-time and operation-time policy",
    ],
    mechanics: [
      "Map generic access bits to the object's concrete rights.",
      "Select the caller's effective token and previous access mode.",
      "Evaluate mandatory policy, privileges, deny ACEs, then allow ACEs until the requested mask is resolved.",
      "Store only the granted rights and authorization state that belong to the checked handle or request.",
    ],
    questions: [
      "Which token and access mode reach SeAccessCheck or the object manager?",
      "Is a kernel caller trusted only because PreviousMode is KernelMode?",
      "Can an authorized handle or per-file context be shared with a different process?",
      "Are FILE_ANY_ACCESS IOCTLs protected by a stricter method-level decision?",
    ],
    apis: [
      {
        name: "SeAccessCheck",
        purpose: "Kernel-mode access check against a security descriptor.",
      },
      {
        name: "SeSinglePrivilegeCheck",
        purpose: "Test a privilege in the current subject context.",
      },
      {
        name: "IoValidateDeviceIoControlAccess",
        purpose: "Require stricter rights for an IOCTL at runtime.",
      },
      { name: "AccessCheck", purpose: "User-mode access-check simulation." },
    ],
    sources: [
      {
        title: "Access control in a driver",
        href: "https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/access-control",
        kind: "primary",
      },
    ],
    related: [
      "security-descriptors",
      "requestor-mode",
      "driver-gates-and-handshakes",
    ],
  },
  {
    slug: "handles-and-access-masks",
    title: "Handles and access masks",
    group: "foundations",
    level: "Foundation",
    summary:
      "A handle is a process-scoped reference to a kernel object whose table entry records the object and the rights granted when it was opened or duplicated.",
    mentalModel:
      "A handle is not authority by itself; its granted access mask is. The same object can be referenced by many handles with different rights, attributes, owners, and lifetime behavior.",
    whyItMatters:
      "Leaking a handle value is weaker than duplicating a powerful handle. Conversely, a low-numbered right such as SERVICE_CHANGE_CONFIG or PROCESS_DUP_HANDLE can be enough to construct a larger chain.",
    enables: [
      "Measure handle-based primitives",
      "Reason about duplication and inheritance",
      "Audit desired versus granted access",
    ],
    mechanics: [
      "A caller supplies desired access while opening or creating an object.",
      "The object manager grants a subset after authorization and records it in the handle table entry.",
      "DuplicateHandle can request the same or a reduced/new access mask, subject to rights on the source process and policy.",
      "Closing the last reference can trigger object teardown even when the name has already disappeared.",
    ],
    questions: [
      "What is the granted access mask?",
      "Which process owns the handle?",
      "Is it inheritable or duplicable?",
      "Does the server re-check client identity when the handle is used?",
    ],
    apis: [
      {
        name: "NtQuerySystemInformation",
        purpose:
          "Enumerate system handles with the appropriate information class.",
      },
      {
        name: "DuplicateHandle",
        purpose: "Duplicate an object handle between processes.",
      },
      {
        name: "NtQueryObject",
        purpose: "Query object type, name, and attributes.",
      },
    ],
    sources: [
      {
        title: "Object handles",
        href: "https://learn.microsoft.com/en-us/windows/win32/sysinfo/object-handles",
        kind: "primary",
      },
    ],
    related: [
      "access-tokens",
      "handle-acquisition",
      "process-thread-token-surface",
    ],
  },
  {
    slug: "irp-and-io-stack",
    title: "IRPs and the Windows I/O stack",
    group: "foundations",
    level: "Intermediate",
    summary:
      "An I/O request packet carries an operation through a stack of device objects, preserving parameters, buffers, status, caller context, and per-layer stack locations.",
    mentalModel:
      "The I/O manager builds an IRP, each driver layer consumes its own IO_STACK_LOCATION, and completion travels back up. Ownership changes at every forward, pend, cancel, and completion boundary.",
    whyItMatters:
      "Buffer lifetime bugs, double completion, cancellation races, RequestorMode mistakes, and trust in data modified by a lower filter all require understanding the full IRP lifecycle—not only the final dispatch function.",
    enables: [
      "Trace IOCTLs and filesystem operations",
      "Audit completion and cancellation",
      "Locate buffer and requestor context",
    ],
    mechanics: [
      "The I/O manager creates an IRP for the major function and target device stack.",
      "The current stack location describes the operation to the active driver.",
      "A driver may complete, pend, transform, or forward the request to the next lower device.",
      "Completion routines unwind the stack while ownership, IRQL, and cancellation state must remain consistent.",
    ],
    questions: [
      "Who owns the IRP now?",
      "Can cancellation race completion?",
      "Which buffer method applies?",
      "Was RequestorMode preserved across a synthesized request?",
    ],
    apis: [
      {
        name: "IoGetCurrentIrpStackLocation",
        purpose: "Read parameters for the current driver layer.",
      },
      {
        name: "IoCallDriver",
        purpose: "Forward an IRP to the next lower device.",
      },
      {
        name: "IoCompleteRequest",
        purpose: "Complete an IRP and begin unwinding.",
      },
      {
        name: "IoSetCompletionRoutine",
        purpose: "Register completion processing.",
      },
    ],
    sources: [
      {
        title: "Introduction to I/O request packets",
        href: `${microsoftDriverDocs}gettingstarted/i-o-request-packets`,
        kind: "primary",
      },
    ],
    related: [
      "ioctl-encoding-and-buffering",
      "filesystem-irps",
      "pnp-and-power",
    ],
  },
  {
    slug: "ioctl-encoding-and-buffering",
    title: "IOCTL encoding and buffer methods",
    group: "foundations",
    level: "Intermediate",
    summary:
      "A 32-bit IOCTL encodes device type, required handle access, function number, and transfer method; those fields determine reachability and how buffers appear in the driver.",
    mentalModel:
      "Decode every IOCTL before reversing its handler. Access bits answer who may send it through an existing handle; method bits answer who maps, probes, locks, and owns each buffer.",
    whyItMatters:
      "FILE_ANY_ACCESS and METHOD_NEITHER are not vulnerabilities by themselves, but they expand the review burden. A strong audit connects the bits to the device DACL, create path, queue, buffer validation, request context, and operation performed.",
    enables: [
      "Decode undocumented interfaces",
      "Choose correct user/kernel buffer handling",
      "Spot overly broad access and pointer-trust bugs",
    ],
    mechanics: [
      "CreateFile or NtCreateFile opens the device with a desired read/write mask.",
      "DeviceIoControl submits an IOCTL; the I/O manager compares its Access bits with the handle's granted access.",
      "The Method bits decide whether data uses a system buffer, MDL-backed direct I/O, or raw user virtual addresses.",
      "The driver validates sizes, state, authorization, and semantics before executing the requested operation.",
    ],
    questions: [
      "What do bits 14–15 require?",
      "Where are input and output lengths checked?",
      "Can the pointer or buffer change after validation?",
      "Is stricter access enforced for sensitive subcommands?",
    ],
    apis: [
      {
        name: "CTL_CODE",
        purpose: "Compose an IOCTL.",
        flags: "DeviceType, Function, Method, Access",
      },
      {
        name: "DeviceIoControl",
        purpose: "Submit a user-mode device control request.",
      },
      {
        name: "IoValidateDeviceIoControlAccess",
        purpose: "Apply stronger runtime access requirements.",
      },
      {
        name: "WdfRequestRetrieveInputBuffer",
        purpose: "Retrieve a validated KMDF input buffer.",
      },
    ],
    demo: {
      title: "Decode an IOCTL value",
      language: "typescript",
      description:
        "Use this small decoder while triaging handlers. It is intentionally read-only and makes the access and transfer assumptions visible.",
      code: `function decodeIoctl(code: number) {\n  return {\n    deviceType: (code >>> 16) & 0xffff,\n    access: (code >>> 14) & 0x3,\n    function: (code >>> 2) & 0xfff,\n    method: code & 0x3,\n  };\n}\n\nconsole.table(decodeIoctl(0x222003));`,
    },
    sources: [
      {
        title: "Defining I/O control codes",
        href: "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes",
        kind: "primary",
      },
    ],
    related: [
      "ioctl-handlers",
      "direct-ioctl-read-write",
      "driver-gates-and-handshakes",
    ],
    featured: true,
  },
  {
    slug: "requestor-mode",
    title: "RequestorMode and PreviousMode",
    group: "foundations",
    level: "Advanced",
    summary:
      "RequestorMode records whether an operation originated from user or kernel mode so probes, object opens, and security checks know whether caller-supplied pointers and authority may be trusted.",
    mentalModel:
      "UserMode means 'treat inputs and access as untrusted.' KernelMode can suppress probes or access checks. A confused or corrupted mode bit can therefore convert a narrow call into a stronger primitive.",
    whyItMatters:
      "Mode confusion is a recurring variant class: a driver synthesizes a request as KernelMode, passes the wrong AccessMode to Zw/Nt routines, or allows PreviousMode manipulation to make later syscalls trust user-controlled arguments.",
    enables: [
      "Explain forced access checks",
      "Audit user-pointer probing",
      "Understand PreviousMode exploitation and its constraints",
    ],
    mechanics: [
      "The kernel records a thread's previous execution mode when crossing the syscall boundary.",
      "I/O and object-manager paths propagate a requestor mode or explicit AccessMode parameter.",
      "Native routines use the mode to decide whether to probe user addresses and enforce access checks.",
      "A safe driver preserves the original trust context or explicitly forces checks when operating on behalf of a user.",
    ],
    questions: [
      "Where did the AccessMode value originate?",
      "Was the request created by user mode or synthesized in kernel mode?",
      "Does OBJ_FORCE_ACCESS_CHECK or IO_FORCE_ACCESS_CHECK apply?",
      "Can mode state be changed only for the current thread and restored reliably?",
    ],
    apis: [
      {
        name: "ExGetPreviousMode",
        purpose: "Return the current thread's previous mode.",
      },
      { name: "ProbeForRead", purpose: "Validate a user-mode readable range." },
      {
        name: "ProbeForWrite",
        purpose:
          "Validate alignment and writable user range; direct writes still require exception handling.",
      },
      {
        name: "ZwCreateFile",
        purpose:
          "Kernel entry whose access-check behavior depends on caller context and object flags.",
      },
    ],
    sources: [
      {
        title: "PreviousMode",
        href: "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode",
        kind: "primary",
      },
      {
        title: "Local privilege escalation via the Windows I/O Manager",
        href: "https://www.microsoft.com/en-us/msrc/blog/2019/03/local-privilege-escalation-via-the-windows-i-o-manager-a-variant-finding-collaboration",
        kind: "case study",
      },
    ],
    related: [
      "previous-mode-manipulation",
      "access-checks",
      "controlled-dereference",
    ],
  },
  {
    slug: "driver-gates-and-handshakes",
    title: "Kernel driver gates and handshakes",
    group: "foundations",
    level: "Advanced",
    summary:
      "A driver gate is a vendor-defined condition layered above Windows device security; a handshake is a multi-step gate that establishes state or a session before sensitive operations become available.",
    mentalModel:
      "Ask what the gate proves and where its state lives. A magic value proves packet format, not caller identity. Per-file authorization can bind state to a handle. Image and registry checks are only as strong as their trust anchor and update model. Capability gates may prove readiness rather than authorization.",
    whyItMatters:
      "Analysts often label every private constant as authentication or treat bypassing a gate as the vulnerability. The real security question is whether the device DACL, IOCTL rights, requestor checks, gate state, and privileged handler jointly enforce the intended caller policy.",
    enables: [
      "Classify packet, authorization, open-time, identity, policy, and readiness gates",
      "Audit whether state is global, per-process, per-handle, or per-request",
      "Separate reverse-engineerable compatibility markers from durable authorization",
    ],
    mechanics: [
      "The device security descriptor determines who may obtain an initial handle.",
      "IOCTL access bits and optional runtime checks constrain which requests reach a handler through that handle.",
      "A private gate validates packet structure, establishes per-file state, recognizes a caller, consults policy, or confirms backend readiness.",
      "Every sensitive handler must still validate authorization, sizes, state transitions, object identity, and the safety of the operation itself.",
      "Review how handles, duplicated handles, PID reuse, restarts, concurrent calls, registry changes, and client updates affect the established state.",
    ],
    questions: [
      "Does the condition prove identity, possession of a secret, protocol compatibility, or only readiness?",
      "Can a different process reuse or duplicate the authorized file handle?",
      "Is the key, hash, resource marker, path, or allowlist writable or reproducible by the threat actor?",
      "Can handshake parsing itself introduce memory-safety, race, or state-machine bugs?",
      "Are privileged subcommands safe even after the intended client is authenticated?",
    ],
    apis: [
      {
        name: "IoCreateDeviceSecure",
        purpose: "Create a named device with explicit SDDL and class GUID.",
      },
      {
        name: "WdfDeviceInitAssignSDDLString",
        purpose: "Assign device security in KMDF.",
      },
      {
        name: "IoValidateDeviceIoControlAccess",
        purpose: "Require stronger handle rights for selected IOCTLs.",
      },
      {
        name: "ZwQueryInformationProcess",
        purpose:
          "Query caller process metadata; path identity alone is a fragile trust anchor.",
      },
      {
        name: "SeAccessCheck",
        purpose: "Evaluate a token against an explicit security policy.",
      },
    ],
    demo: {
      title: "Model authorization as per-file state",
      language: "c",
      description:
        "This defensive pseudocode shows the key invariant: authorization belongs to the file object, is established once through a validated transition, and is checked again before sensitive commands. Real code must add synchronization, requestor-token policy, cleanup, and complete buffer validation.",
      code: `typedef struct _FILE_CONTEXT {\n    BOOLEAN Authorized;\n    HANDLE BoundProcessId;\n} FILE_CONTEXT;\n\nNTSTATUS Authorize(FILE_CONTEXT* ctx, const AUTH_REQUEST* request) {\n    if (!ValidatePacketShape(request)) return STATUS_INVALID_PARAMETER;\n    if (!ValidateRequestorPolicy(request)) return STATUS_ACCESS_DENIED;\n\n    ctx->Authorized = TRUE;\n    ctx->BoundProcessId = PsGetCurrentProcessId();\n    return STATUS_SUCCESS;\n}\n\nNTSTATUS SensitiveCommand(FILE_CONTEXT* ctx, const COMMAND* command) {\n    if (!ctx->Authorized) return STATUS_ACCESS_DENIED;\n    if (ctx->BoundProcessId != PsGetCurrentProcessId()) return STATUS_ACCESS_DENIED;\n    return ValidateAndExecute(command);\n}`,
    },
    sources: [
      {
        title: "Kernel Driver Gates and Handshakes",
        href: "https://www.exploitpack.com/blogs/news/kernel-driver-gates-and-handshakes",
        kind: "case study",
      },
      {
        title: "Applying security descriptors on the device object",
        href: "https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/applying-security-descriptors-on-the-device-object",
        kind: "primary",
      },
      {
        title: "Defining I/O control codes",
        href: "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes",
        kind: "primary",
      },
    ],
    related: [
      "ioctl-encoding-and-buffering",
      "access-checks",
      "weak-device-dacl",
      "ioctl-handlers",
    ],
    featured: true,
  },
];

export const handbookConcepts = [
  ...concepts,
  ...primitiveConcepts,
  ...vulnerabilityClassConcepts,
  ...attackSurfaceConcepts,
  ...driverTypeConcepts,
  ...lpeConcepts,
  ...mitigationConcepts,
  ...workflowConcepts,
];

export const handbookConceptBySlug = new Map(
  handbookConcepts.map((concept) => [concept.slug, concept]),
);

export function getHandbookGroup(id: HandbookGroupId) {
  return handbookGroups.find((group) => group.id === id);
}

export function getConceptsForGroup(id: HandbookGroupId) {
  return handbookConcepts.filter((concept) => concept.group === id);
}
