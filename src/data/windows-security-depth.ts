import type {
  ConceptDemo,
  HandbookConcept,
  HandbookGroupId,
} from "./windows-security-handbook";

export interface DeepDiveInvariant {
  expected: string;
  failure: string;
  securityEffect: string;
}

export interface DeepDiveExample {
  title: string;
  setup: string;
  steps: string[];
  observation: string;
  lesson: string;
}

export interface DeepDiveConstraint {
  dimension: string;
  question: string;
  evidence: string;
}

export interface ConceptDeepDive {
  context: string[];
  invariant: DeepDiveInvariant;
  example: DeepDiveExample;
  constraints: DeepDiveConstraint[];
  evidence: string[];
  pitfalls: string[];
  defenses: string[];
  lab: {
    objective: string;
    setup: string[];
    procedure: string[];
    expected: string[];
    cleanup: string[];
    demo: ConceptDemo;
  };
}

interface GroupDepthProfile {
  context: string[];
  invariant: string;
  failure: string;
  evidence: string[];
  pitfalls: string[];
  defenses: string[];
  labSetup: string[];
  labProcedure: string[];
  labExpected: string[];
}

const groupProfiles: Record<HandbookGroupId, GroupDepthProfile> = {
  foundations: {
    context: [
      "Windows security behavior emerges from several contracts acting together: object identity, handle rights, token state, requestor context, namespace resolution, lifetime, and the implementation of the final privileged operation. Reading only the last function in a call chain usually hides the decision that actually granted authority.",
      "A foundation concept should therefore be traced through creation, lookup, use, duplication, and teardown. At each transition, record the active principal, the object being referenced, the granted access mask, and whether the decision is cached in a handle or recomputed for the operation.",
      "Build awareness matters because internal layouts, supported information classes, framework behavior, mitigation state, and even documented edge cases change. A correct explanation names the stable contract first, then identifies which details are build-specific observations.",
    ],
    invariant:
      "The documented object, identity, and access-control contract remains true from the least-trusted input through the final privileged action.",
    failure:
      "A component confuses identity, namespace, handle rights, mode, object lifetime, or cached state and performs an operation under stronger authority than the original decision allowed.",
    evidence: [
      "The exact token, integrity level, privileges, and session of the initiating caller.",
      "The object type, canonical identity, security descriptor, desired access, and granted access stored in the handle.",
      "A call stack or trace showing where the security decision is made and which context reaches it.",
      "Positive and negative tests that differ by one right, token property, namespace object, or requestor-mode condition.",
    ],
    pitfalls: [
      "Treating a process name, path, signature, PID, or packet marker as proof of caller identity without naming the trust anchor.",
      "Reading a security descriptor but never decoding the object-specific rights that the ACE actually grants.",
      "Assuming the access check happens on every operation when the decisive result may already be stored in the opened handle.",
    ],
    defenses: [
      "Perform authorization against the caller token and the exact securable object, using object-specific rights rather than generic labels.",
      "Bind protocol state to the narrowest lifetime that owns it, normally the file or connection context, and invalidate it during cleanup.",
      "Preserve requestor context across asynchronous work and force access checks when privileged code opens an object on behalf of a user.",
      "Log enough identity, object, and access-mask information to reconstruct the decision without recording secrets or unstable pointers.",
    ],
    labSetup: [
      "Use a disposable Windows VM with the exact build and symbols recorded.",
      "Create two local test principals whose group membership or integrity level differs by one relevant property.",
      "Keep Process Explorer, WinObj, AccessChk, or equivalent read-only inspection tools available.",
    ],
    labProcedure: [
      "Capture the caller token and the target object's security descriptor before invoking the operation.",
      "Open the object with the smallest requested mask and record the granted handle rights.",
      "Repeat the observation after changing one identity or access-control condition, not several at once.",
      "Correlate the user-mode result with a trace or debugger observation at the security decision.",
    ],
    labExpected: [
      "A reproducible statement of which principal can obtain which right to which object.",
      "A negative control that fails at the expected layer and with the expected status.",
      "A build-pinned trace that distinguishes open-time policy from operation-time validation.",
    ],
  },
  primitives: {
    context: [
      "A primitive is a measured capability, not a vulnerability name and not the final impact. Two bugs in unrelated subsystems can produce the same primitive, while two instances of the same bug class can produce very different control over address, value, size, timing, identity, and repetition.",
      "Primitive analysis is most useful when written as a contract. State exactly what the researcher controls, what remains fixed, which address space or namespace is affected, how many times the operation can be repeated, and what causes failure. Those constraints determine whether a later conversion is realistic.",
      "The next stage is composition. A constrained capability may require an information disclosure, object spray, privileged consumer, namespace redirection, race, token transition, or mitigation-specific target before it becomes security impact. Every conversion should name its additional assumptions instead of hiding them in the word 'arbitrary.'",
    ],
    invariant:
      "A less-trusted caller cannot direct a privileged component to read, write, create, delete, redirect, map, invoke, or impersonate outside the objects and bounds authorized by the interface.",
    failure:
      "Attacker-controlled data influences a privileged target, value, path, identity, or timing dimension beyond the interface's intended capability.",
    evidence: [
      "Independent tests for target control, value control, transfer width, alignment, address-space limits, and repetition.",
      "A before/after observation of the exact object or bytes affected, including failures at boundary values.",
      "The least-privileged starting identity and every handle, privilege, race, or information requirement used by the conversion.",
      "A stability record across reboots, allocator noise, concurrent activity, and the exact mitigation configuration.",
    ],
    pitfalls: [
      "Calling a capability arbitrary after testing only one convenient target or one value.",
      "Jumping from corruption to SYSTEM without documenting address discovery, target selection, triggering, and cleanup.",
      "Confusing an administrator-to-kernel capability with a standard-user local privilege escalation path.",
    ],
    defenses: [
      "Constrain both the target and the operation: validate ranges, object types, ownership, access rights, state, and transfer size before use.",
      "Capture caller-controlled inputs once, use overflow-safe arithmetic, and avoid re-resolving attacker-mutable names after validation.",
      "Reduce exposed authority so the backend operation cannot address kernel memory, arbitrary files, raw hardware, or unrelated security contexts.",
      "Design telemetry around the sensitive operation and its parameters rather than a reverse-engineerable packet marker.",
    ],
    labSetup: [
      "Use an isolated snapshot with a harmless test object or sacrificial buffer as the only permitted target.",
      "Record the exact binary, symbols, allocator settings, verifier state, and mitigations.",
      "Prepare a constraint table before triggering anything: target, value, width, count, timing, context, and failure mode.",
    ],
    labProcedure: [
      "Vary one control dimension at a time and record the smallest successful and failing values.",
      "Verify the effect through an independent observation path rather than trusting the request's return status.",
      "Test repeatability and teardown behavior, then determine which additional primitive a real conversion would require.",
      "Restore the snapshot and reproduce the same measurements from the recorded procedure.",
    ],
    labExpected: [
      "A capability statement that avoids the word arbitrary unless every relevant dimension was tested.",
      "A constraint matrix with positive, negative, and boundary observations.",
      "A composition graph that labels every missing prerequisite between the measured primitive and final impact.",
    ],
  },
  "vulnerability-classes": {
    context: [
      "A vulnerability class names the invariant that failed, not merely the crash shape. The first invalid state transition may happen far earlier than the faulting instruction, so root-cause analysis works backward from ownership, bounds, identity, type, initialization, synchronization, or protocol assumptions.",
      "A useful explanation separates root cause from primitive. A use-after-free may become a stale read, a controlled call target, or no controllable capability at all. An authorization bug may expose one low-impact operation or a complete privileged file primitive. The class guides where to look for variants; the primitive determines composition.",
      "Patch analysis should translate a changed branch, lock, reference, probe, initialization, or access check into a sentence about the restored invariant. That sentence is then searched across sibling handlers and alternate representations rather than matching only the patched function name.",
    ],
    invariant:
      "Every privileged operation uses valid bounds, initialized data, the intended object type and identity, a live owned reference, synchronized state, and authorization tied to the real caller.",
    failure:
      "At least one of those properties becomes false while privileged code continues as if the original invariant still held.",
    evidence: [
      "The earliest instruction or state transition that makes the invariant false, not only the eventual crash.",
      "Object lifetime, allocation, reference, lock, type, length, and caller-controlled data at the failing transition.",
      "A minimized reproducer plus negative controls that preserve the invariant.",
      "The vulnerable/fixed diff expressed as a semantic rule and tested against sibling paths.",
    ],
    pitfalls: [
      "Naming the bug from the exception code without proving the earlier invariant violation.",
      "Assuming a memory-safety crash is exploitable without measuring attacker control and mitigation constraints.",
      "Treating one added check as complete without searching alternate handlers, integer representations, and concurrent paths.",
    ],
    defenses: [
      "Make ownership, lengths, types, and protocol states explicit in interfaces and keep validation adjacent to use.",
      "Use framework helpers, safe arithmetic, reference-counting conventions, and synchronization primitives consistently across sibling paths.",
      "Authorize the operation against the requestor and exact object after canonicalization, not against presentation-layer metadata.",
      "Add regression tests for the vulnerable shape, boundary values, teardown, concurrency, and alternate entry points.",
    ],
    labSetup: [
      "Pin vulnerable and fixed builds with matching symbols and hashes.",
      "Enable the narrow verifier or instrumentation settings relevant to the suspected invariant.",
      "Prepare a deterministic reproducer and a debugger script that captures the involved state before corruption.",
    ],
    labProcedure: [
      "Write the expected invariant before setting breakpoints.",
      "Break at creation, validation, state transition, use, and teardown to find the first divergence.",
      "Change one input, schedule, size, type, or permission property to create a negative control.",
      "Compare the fixed build and search sibling paths for the same missing invariant.",
    ],
    labExpected: [
      "A root-cause sentence naming the object, property, and invalid transition.",
      "A separate primitive statement describing actual attacker control.",
      "A patch-derived variant rule with at least one true and one false test case.",
    ],
  },
  "attack-surfaces": {
    context: [
      "An attack surface is a reachable protocol boundary, not simply a module name. The relevant unit is the endpoint plus operation, caller identity, state prerequisites, buffer model, object lookup, and privileged side effect. A large subsystem may expose several unrelated surfaces with different trust assumptions.",
      "Enumeration should cover registration and lifecycle. Devices, RPC endpoints, callbacks, filter registrations, shared sections, files, packets, COM classes, and service methods can appear only after hardware, policy, session, or application state is established. Missing the activation condition produces misleading reachability claims.",
      "For each entry point, trace input capture, validation, canonicalization, authorization, object reference, asynchronous handoff, completion, cancellation, and cleanup. Many defects live between those stages rather than inside the obvious parser.",
    ],
    invariant:
      "Every reachable privileged entry point validates the real caller, captures untrusted input safely, enforces protocol state, references the intended object, and constrains the final side effect.",
    failure:
      "A less-trusted caller reaches an operation or state transition with unchecked data, insufficient rights, confused identity, stale lifetime, or excessive backend authority.",
    evidence: [
      "Endpoint registration, security descriptor, operation identifiers, activation conditions, and the least-privileged caller that can connect.",
      "Dispatch or handler mapping from the external operation to the final privileged sink.",
      "Buffer method, size relationships, requestor context, state machine, cancellation, and teardown observations.",
      "Coverage or traces proving that the test reaches meaningful code rather than only an early rejection path.",
    ],
    pitfalls: [
      "Listing exported methods or IOCTL numbers without proving that a standard user can obtain the required endpoint or handle.",
      "Fuzzing random bytes before modeling initialization, sequencing, checksums, object handles, and reset behavior.",
      "Ignoring cleanup, cancellation, power, session, and concurrent-close paths because they are outside the main request handler.",
    ],
    defenses: [
      "Apply least-privilege endpoint security before parsing and use operation-specific access checks for sensitive methods.",
      "Use a small, versioned protocol with explicit lengths, states, ownership, and fail-closed transitions.",
      "Capture untrusted data once, validate object identity after lookup, and retain references across asynchronous work.",
      "Instrument rejected and sensitive operations so protocol abuse and unexpected caller classes are observable.",
    ],
    labSetup: [
      "Use a disposable VM and record which service, driver, device, session, hardware, or policy activates the endpoint.",
      "Enumerate endpoint security and operation identifiers without sending mutating requests.",
      "Prepare tracing or coverage that can distinguish dispatch, validation, backend operation, completion, and cleanup.",
    ],
    labProcedure: [
      "Open or connect with the least access possible and record the exact token and granted rights.",
      "Send one well-formed, read-only request and map every handler transition it reaches.",
      "Vary length, state order, identity, cancellation, or object lifetime one dimension at a time.",
      "Confirm reset and cleanup before repeating from a clean snapshot.",
    ],
    labExpected: [
      "An endpoint-to-sink map with authorization and validation decisions labeled.",
      "A state diagram that includes open/create, normal operation, cancellation, cleanup, and close.",
      "Coverage evidence and negative controls for rejected callers or malformed states.",
    ],
  },
  "driver-types": {
    context: [
      "Driver family predicts authority and lifecycle. A filesystem filter reasons about names, streams, reparse behavior, and recursive I/O; a network driver handles packets, offload state, and asynchronous completion; a vendor utility may expose raw hardware operations through a custom device protocol.",
      "Classification is not a vulnerability verdict. It is a way to choose the right entry points, framework contracts, object lifetimes, concurrency model, and privileged resources for review. The same API can be safe in an internal path and dangerous when its arguments are derived from a user-reachable request.",
      "Review the complete deployment unit: INF, service configuration, device interface class, security descriptor, companion service, update channel, signatures, block policy, and unload behavior. Security bugs frequently sit in the glue between the driver and its user-mode client.",
    ],
    invariant:
      "The driver exposes only the authority required by its role, through framework-correct interfaces whose access, buffer, lifecycle, and device-state contracts remain valid.",
    failure:
      "A driver family-specific resource or lifecycle transition is made reachable through weak device policy, excessive operations, unsafe framework use, or confused state between kernel, user mode, and hardware.",
    evidence: [
      "Driver image, version, signer, service/INF configuration, device stack, framework, and load trigger.",
      "Device names/interfaces, security descriptors, dispatch tables, callbacks, management endpoints, and companion processes.",
      "The privileged resources controlled by each operation and whether caller data reaches their sensitive arguments.",
      "PnP, power, unload, cancellation, surprise-removal, update, and concurrent request behavior.",
    ],
    pitfalls: [
      "Scoring risk from dangerous imports without proving a call path from a reachable entry point.",
      "Reviewing only the SYS file while ignoring INF security, registry policy, services, clients, firmware, and update logic.",
      "Applying one driver's exploitation pattern to another family without checking framework and lifecycle differences.",
    ],
    defenses: [
      "Minimize device exposure and separate diagnostic, update, and runtime operations into least-privilege interfaces.",
      "Use the driver framework's buffer, queue, cancellation, synchronization, and object-parenting contracts consistently.",
      "Remove generic memory, register, port, MSR, firmware, process, or file operations from production interfaces.",
      "Ship revocation, update, telemetry, and compatibility plans with the driver rather than treating signing as the final control.",
    ],
    labSetup: [
      "Use a VM snapshot that matches the driver version, INF, companion software, and required virtual hardware.",
      "Collect the driver stack, services, interfaces, security descriptors, symbols, and loaded module hashes.",
      "Prepare Driver Verifier or framework diagnostics narrowly enough to preserve useful behavior.",
    ],
    labProcedure: [
      "Map load, start, device creation, client connection, normal request, cancellation, cleanup, stop, and unload.",
      "Trace one benign request from the user-mode client through the device stack to the final resource.",
      "Record which arguments are caller controlled and where framework helpers validate or retain them.",
      "Repeat during one family-specific lifecycle event such as power change, file teardown, packet cancellation, or device removal.",
    ],
    labExpected: [
      "A complete deployment and authority map, not only an import list.",
      "An entry-point table with caller, state, buffer model, backend resource, and cleanup owner.",
      "At least one family-specific lifecycle trace and a list of assumptions requiring further testing.",
    ],
  },
  "lpe-services": {
    context: [
      "A local privilege-escalation chain requires a weaker principal, a controllable object or request, a stronger principal, and a final sensitive action. The middle of the chain may involve a service DACL, writable file, registry value, token, named pipe, COM activation, scheduled task, installer, or confused-deputy request.",
      "Configuration weakness is not automatically impact. A user may be able to start a service but not change its binary path; write a directory but not the loaded file; register a COM class that only the same user activates; or impersonate a client at a level that cannot access the intended resource. Object-specific rights and the privileged consumer must be proved.",
      "Reliable analysis resolves names exactly as the privileged component does. Quote parsing, environment expansion, search order, WOW64 views, service-host groups, reparse points, impersonation, session boundaries, and repair/rollback behavior can change which object is ultimately used.",
    ],
    invariant:
      "A low-privilege user cannot control the code, configuration, path, token, endpoint, or object consumed by a more privileged principal for a sensitive operation.",
    failure:
      "A stronger principal consumes attacker-controlled state or delegates authority through an endpoint without binding the action to the real caller and intended object.",
    evidence: [
      "The starting token and the exact object-specific right available to it.",
      "The controlled file, directory, registry value, service object, task, endpoint, COM registration, handle, or token property.",
      "A trace showing the stronger principal resolving or consuming that state.",
      "Final proof based on token identity or protected-object access, plus cleanup and detection artifacts.",
    ],
    pitfalls: [
      "Reporting a writable path without proving that a privileged component loads, executes, moves, deletes, or trusts it.",
      "Equating SERVICE_START, generic write access, or one ACE string with SERVICE_CHANGE_CONFIG, WRITE_DAC, or executable replacement.",
      "Calling an administrator-consent or UAC bypass a standard-user-to-SYSTEM LPE without stating the initial token and boundary.",
    ],
    defenses: [
      "Harden service, task, file, directory, registry, pipe, RPC, and COM permissions using object-specific least privilege.",
      "Use canonical absolute paths, safe DLL loading, protected install locations, and handle-based operations when object identity matters.",
      "Impersonate the client for resource access or perform an explicit authorization decision before returning to a privileged token.",
      "Monitor changes to privileged configuration and the privileged consumer event that turns configuration control into execution or protected-object access.",
    ],
    labSetup: [
      "Use a disposable non-domain VM with one standard-user account and a separately administered snapshot.",
      "Inventory services, tasks, COM registrations, privileged files, registry keys, endpoints, and token privileges read-only.",
      "Choose a benign lab-owned object; do not replace system binaries or weaken production permissions.",
    ],
    labProcedure: [
      "Decode the exact access mask available to the standard user and verify it with a handle-based query.",
      "Trace how the privileged consumer resolves and opens the controlled object, including impersonation state.",
      "Use a harmless marker file or event in the lab to prove the consumer action without spawning a shell.",
      "Restore permissions and content, reboot if required, and repeat from a clean snapshot.",
    ],
    labExpected: [
      "A complete weaker-principal to stronger-principal chain with no implied transitions.",
      "A negative control showing that removing the one relevant right or path condition breaks the chain.",
      "Detection and cleanup notes covering both the configuration change and privileged consumption event.",
    ],
  },
  mitigations: {
    context: [
      "A mitigation invalidates an exploit assumption; it does not make every underlying bug harmless. Analysis starts by naming the assumption being removed: executable data, predictable addresses, untrusted indirect targets, writable protected state, user mappings, unsigned code, or access to a protected process.",
      "Support, configuration, and enforcement are different facts. A CPU may support a feature that firmware disables; Windows may expose a policy that is not active for the target process; a driver may be compatible with HVCI while the system is not running it. Record active runtime state on the exact build.",
      "The useful question is how the exploit graph changes. A control may force an information disclosure, valid-call-target strategy, data-only target, different allocator object, signed-driver path, or privileged service route. The residual path and its new assumptions should be documented explicitly.",
    ],
    invariant:
      "The platform enforces the mitigation's protected property for the relevant process, kernel component, page, call target, object, or code-loading decision on the exact target.",
    failure:
      "The control is absent, partially enabled, bypassed through an allowed path, or irrelevant to the primitive and target selected by the chain.",
    evidence: [
      "OS build, SKU, update state, CPU/firmware support, policy, boot configuration, and runtime enforcement state.",
      "A positive control that the mitigation blocks the prohibited action and a compatible negative or allowed action.",
      "Compiler/image metadata where relevant, plus debugger or system telemetry confirming enforcement.",
      "A before/after exploit graph showing exactly which assumption and edge changed.",
    ],
    pitfalls: [
      "Inferring runtime protection from a PE flag, registry value, marketing name, or supported-feature list alone.",
      "Calling a technique a bypass when it actually chooses a target outside the mitigation's scope.",
      "Testing on a different build or policy state and carrying the conclusion forward without revalidation.",
    ],
    defenses: [
      "Enable the control through supported policy and verify runtime enforcement across representative hardware and workloads.",
      "Combine exploit mitigations with least privilege, attack-surface reduction, code integrity, patching, and revocation.",
      "Monitor policy drift, compatibility exceptions, disabled states, and the alternate behaviors attackers use after the control activates.",
      "Document support and rollback requirements so operational pressure does not silently disable the protection.",
    ],
    labSetup: [
      "Prepare two otherwise identical snapshots that differ only in the mitigation state being studied.",
      "Record build, firmware, virtual-machine settings, policy, boot state, image metadata, and runtime queries.",
      "Choose a benign probe that exercises the protected property without requiring a full exploit chain.",
    ],
    labProcedure: [
      "Confirm support and active enforcement independently.",
      "Run the same probe on both snapshots and capture the status, event, or debugger decision.",
      "Map the blocked exploit assumption and test whether a data-only or allowed-path operation remains possible.",
      "Restore the original policy and confirm the lab did not leave boot or security settings altered.",
    ],
    labExpected: [
      "A build-specific proof that distinguishes supported, configured, and enforced states.",
      "A precise statement of the exploit edge removed by the mitigation.",
      "A residual-risk list covering remaining primitives, targets, exceptions, and operational dependencies.",
    ],
  },
  "research-workflow": {
    context: [
      "A research workflow is an evidence pipeline. It converts a falsifiable question into pinned artifacts, repeatable observations, a confidence-scored claim, and enough provenance for another researcher to reproduce or reject the result.",
      "Tools are useful only in relation to a question. A decompiler match is not a root cause, an import is not reachability, coverage is not exploitability, and a debugger screenshot is not a reproducible experiment. Each tool output should feed a named decision in the investigation.",
      "Good workflow design preserves negative results and uncertainty. Unknown values stay unknown, inferred tags remain distinct from observed facts, and automation narrows review rather than converting heuristic matches into vulnerability claims.",
    ],
    invariant:
      "Every technical claim is tied to versioned artifacts, a reproducible method, direct evidence, explicit assumptions, and a confidence level appropriate to what was actually observed.",
    failure:
      "Tool output, stale metadata, an unpinned environment, or an untested inference is promoted into a factual security claim or generalized beyond its evidence.",
    evidence: [
      "Hashes, versions, symbols, configuration, mitigations, tool versions, commands, and timestamps for the target.",
      "The hypothesis, expected falsifying observation, actual observation, and negative controls.",
      "Raw traces, diffs, crashes, coverage, debugger automation, or corpus records needed to regenerate the conclusion.",
      "A distinction between observed, documented, inferred, likely, and confirmed fields.",
    ],
    pitfalls: [
      "Starting with a tool and collecting output without a question that changes based on the result.",
      "Discarding negative results, timeouts, unreachable paths, and environment differences that constrain the conclusion.",
      "Using one risk score to hide separate uncertainty in exposure, capability, severity, deployment, and confidence.",
    ],
    defenses: [
      "Version schemas, tools, corpora, and lab images; preserve provenance and make regeneration a first-class operation.",
      "Require manual validation and reachability evidence before high-confidence security labels.",
      "Use regression corpora containing vulnerable, fixed, benign, and ambiguous samples.",
      "Publish assumptions, limitations, safe reproduction steps, mitigations, and cleanup with the technical result.",
    ],
    labSetup: [
      "Create a version-pinned workspace with immutable input artifacts and a disposable execution environment.",
      "Write one falsifiable question and the exact observation that would change the current hypothesis.",
      "Record tool versions, configuration, symbols, hashes, and output schema before analysis.",
    ],
    labProcedure: [
      "Run the smallest automated step that answers the current question and retain raw output.",
      "Validate one result manually and run at least one known-positive and one known-negative control.",
      "Assign confidence separately from severity and record every assumption required by the claim.",
      "Regenerate the result in a clean workspace from the documented command sequence.",
    ],
    labExpected: [
      "A reproducible evidence bundle rather than a screenshot-only conclusion.",
      "A claim whose confidence is justified by reachability and manual validation.",
      "A list of negative results, unknowns, and next experiments that would reduce uncertainty.",
    ],
  },
};

const scenarioBySlug: Record<string, string> = {
  "trust-boundaries":
    "A standard user sends a request to a SYSTEM service that opens a file after temporarily impersonating the client; the example tracks exactly where the service reverts and which token performs the final open.",
  "object-manager-namespaces":
    "A client opens a DOS device path whose symbolic link resolves into the Object Manager namespace; the example distinguishes the link object, target device, session namespace, and final handle.",
  "access-tokens":
    "Two processes run under the same account name but carry different integrity levels and enabled privileges; the example explains why their access-check results differ.",
  "security-descriptors":
    "A service object grants a group SERVICE_START but not SERVICE_CHANGE_CONFIG; the example decodes the DACL and avoids calling the entire service writable.",
  "access-checks":
    "A server evaluates a requested operation against an impersonation token and object-specific generic mapping; the example follows desired access through mapped and granted rights.",
  "handles-and-access-masks":
    "A low-right process handle is duplicated into another process; the example shows that duplication transfers existing granted rights rather than reinterpreting the target process name.",
  "irp-and-io-stack":
    "A user request crosses a filter and function driver before completion; the example records stack locations, buffer ownership, pending status, cancellation, and the layer that completes the IRP.",
  "ioctl-encoding-and-buffering":
    "A private IOCTL uses METHOD_NEITHER and FILE_ANY_ACCESS; the example decodes the control code and traces how the user pointers arrive at the dispatch routine.",
  "requestor-mode":
    "A driver queues work from a user request and later opens a file from a worker thread; the example checks whether the original requestor mode and forced access-check intent survive the handoff.",
  "driver-gates-and-handshakes":
    "A vendor client sends an authorization IOCTL that sets state on one file handle before privileged commands; the example tests handle duplication, process identity, cleanup, and whether the gate proves authorization or only protocol compatibility.",
  "arbitrary-read":
    "A diagnostic driver accepts an address and length then copies bytes into an output buffer; the example measures readable address ranges, transfer width, repetition, fault behavior, and whether the caller can choose the process or address space.",
  "information-leak":
    "A query returns a structure whose padding contains a kernel pointer; the example separates a stable address disclosure from random uninitialized bytes and tests whether the leaked value removes a real uncertainty in a later chain.",
  "arbitrary-write":
    "A privileged handler copies caller-controlled bytes to a caller-selected address; the example measures independent destination, value, width, alignment, address-space, and repeatability constraints before selecting any target.",
  "write-what-where":
    "A METHOD_NEITHER handler writes a controlled value through an unprobed output pointer; the example traces the pointer from user mode, confirms the exact write width on a sacrificial buffer, and treats address discovery as a separate prerequisite.",
  "constrained-write":
    "A bug can zero four bytes at a chosen address but cannot choose another value; the example searches for fields where zero has a meaningful transition while documenting alignment, width, and one-shot constraints.",
  "arbitrary-increment-decrement":
    "A reference-count operation can be redirected to a selected address; the example measures the fixed delta, atomicity, repetition limit, wrap behavior, and whether adjacent packed fields remain unchanged.",
  "bit-manipulation":
    "A handler exposes set, clear, and toggle operations on a caller-selected bit index; the example verifies mask construction, field width, preserved neighboring bits, and which state transitions are reachable.",
  "controlled-dereference":
    "A confused structure pointer makes privileged code read or write through a selected address while the transferred value remains fixed by program state; the example records direction, width, value source, and fault handling.",
  "controlled-call-target":
    "A stale callback pointer can be replaced with an attacker-influenced target; the example distinguishes target control from valid-call-target restrictions, calling convention, argument control, IRQL, and safe return requirements.",
  "direct-ioctl-read-write":
    "A signed hardware utility exposes kernel and physical memory operations through private IOCTLs; the example decodes access bits and gates, then proves which backend arguments a standard or administrative caller actually controls.",
  "dma-mmio-access":
    "A utility driver maps a caller-selected physical range or device BAR into user mode; the example records IOMMU state, allowed ranges, cache attributes, mapping lifetime, and whether peer or system memory is reachable.",
  "mdl-mapping":
    "A driver builds an MDL for a caller-influenced virtual address and maps the described pages into user mode; the example checks probing, locking, access mode, cache type, permissions, process context, and cleanup.",
  "pipe-attribute-primitives":
    "A stale named-pipe attribute object is replaced with controlled pool data; the example follows allocation size, object lookup, read-back behavior, pool placement, and the step that converts replacement into a measured read or write.",
  "pool-overflow-to-read-write":
    "A variable-length kernel allocation overruns into a neighboring object; the example first proves overflow geometry, then chooses a sacrificial adjacent object whose length and pointer fields can expose a bounded read/write interface.",
  "pte-manipulation":
    "A measured kernel write reaches one page-table entry; the example derives the entry for a lab page, records present/write/user/NX transitions, performs a TLB-consistent observation, and restores the original value.",
  "registry-based-primitives":
    "A privileged driver reads a low-privilege-writable registry value and later treats it as an address, path, or capability selector; the example separates registry write access, reload timing, parsing, and the privileged consumer.",
  "token-manipulation":
    "A kernel write can alter selected token fields; the example distinguishes identity, privileges, groups, integrity, restrictions, and reference ownership rather than treating every token modification as equivalent to SYSTEM.",
  "acl-security-descriptor-manipulation":
    "A privileged object retains an attacker-influenced security descriptor pointer; the example decodes owner, DACL presence, ACE order, inheritance, and object-specific rights, then verifies access with a separate test token.",
  "io-ring":
    "A corruption changes an I/O ring's registered-buffer metadata; the example pins the build, validates handle and object layout, measures buffer-table control on lab memory, and records which I/O operations create a repeatable data movement primitive.",
  "kuser-shared-data":
    "A constrained kernel write can reach a shared user/kernel data page; the example identifies fields with stable semantics on the pinned build and separates writable shared data from executable or control-flow assumptions.",
  "named-pipe-objects":
    "A researcher sprays named-pipe queue or attribute objects to occupy a freed pool slot; the example records object size, pool type, allocation/free sequence, read-back interface, and cleanup rather than assuming deterministic placement.",
  "palette-bitmap-objects":
    "A legacy graphics object pair is used to convert pointer corruption into manager/worker reads and writes; the example documents build availability, object fields, call path, mitigation state, and why the historical layout may not transfer.",
  "pool-spray-feng-shui":
    "A UAF lab needs a controlled object in a recently freed slot; the example measures size class, processor locality, lookaside behavior, allocation noise, free order, and success probability across clean reboots.",
  "previous-mode-manipulation":
    "A constrained write changes one thread's PreviousMode in a lab; the example verifies thread affinity, forced access-check behavior, user-pointer probing differences, restoration, and why the effect is not process-global.",
  "token-swapping":
    "A kernel write replaces the current process token reference with a token from a stronger process; the example treats address discovery, EX_FAST_REF low bits, reference lifetime, target selection, and restoration as separate steps.",
  "wnf-state-data":
    "A WNF state-data allocation is shaped or replaced to obtain controlled kernel metadata; the example traces state-name permissions, allocation size, read/write APIs, lifetime, and the exact corrupted fields used by the conversion.",
  "arbitrary-file-read":
    "A SYSTEM service accepts a path and returns file content; the example checks client impersonation, canonical identity, share flags, reparse traversal, backup semantics, and whether the caller can select protected files.",
  "arbitrary-file-create":
    "A privileged updater creates a file at a caller-influenced path; the example records create disposition, parent-directory identity, owner/DACL inheritance, reparse handling, content control, and collision behavior.",
  "arbitrary-file-write":
    "A privileged component writes caller data to a path selected before an asynchronous handoff; the example tests truncation versus append, offset and content control, link following, impersonation, and final file identity.",
  "arbitrary-file-delete":
    "A cleanup service deletes a caller-selected path as SYSTEM; the example proves deletion of a sacrificial protected file, then separately studies whether rollback, repair, or privileged recreation converts deletion into a stronger primitive.",
  "arbitrary-file-move":
    "A privileged service renames a lab file between attacker-influenced directories; the example measures source and destination control, replace semantics, volume boundaries, link handling, security descriptor retention, and rollback.",
  "arbitrary-directory-create":
    "A provisioning service creates nested directories for a supplied destination; the example checks parent resolution, intermediate-component races, owner/DACL inheritance, junction traversal, and whether the caller controls later contents.",
  "arbitrary-directory-delete":
    "A privileged maintenance operation recursively removes a selected lab directory; the example records traversal rules, link behavior, mount boundaries, open-handle failures, and whether a privileged consumer later recreates the tree.",
  "junction-mount-point":
    "A low-privilege directory junction redirects a privileged path traversal to another volume location; the example pins the source handle, target substitute name, follow policy, timing, and final opened file identity.",
  "object-manager-symbolic-links":
    "An Object Manager symbolic link is created in a namespace visible to a privileged client; the example distinguishes directory permissions, link lifetime, session/global visibility, target parsing, and the consumer's open flags.",
  "hard-link-creation":
    "A file hard link gives a second name to the same lab file record; the example verifies volume and filesystem constraints, object identity, link permissions, protected-file policy, and which privileged operation acts on the shared object.",
  "reparse-point-substitution":
    "A privileged worker validates a directory then later follows a reparse point inserted beneath it; the example uses file IDs and handles to show the checked object differs from the consumed object.",
  "oplock-assisted-race":
    "An opportunistic lock pauses a privileged file operation after validation but before the final open or rename; the example records the exact blocked IRP, namespace mutation, release timing, and whether the consumer revalidates identity.",
  "privileged-file-copy-restore":
    "A backup or updater service copies attacker-controlled content into a protected lab destination; the example checks source trust, destination identity, overwrite policy, inherited security, signatures, and the privileged trigger that consumes the file.",
  "buffer-overflow":
    "A driver allocates a fixed kernel buffer but copies a caller-supplied length; the example finds the first out-of-bounds byte, allocation class, adjacent object, exception behavior, and whether copied bytes remain controllable after framework handling.",
  "out-of-bounds-read":
    "A query trusts an element index beyond a variable-length array; the example measures the readable range, returned length, allocation boundaries, uninitialized versus adjacent data, and whether the disclosure is stable enough to matter.",
  "integer-overflow":
    "A count multiplied by an element size wraps before allocation but the original count controls the later copy; the example records integer widths, signedness, promotion, boundary values, allocation size, and the exact safe-arithmetic check added by the fix.",
  "use-after-free":
    "An asynchronous request keeps a raw object pointer after another path closes the owning handle; the example follows reference acquisition, free, slot reuse, stale use, attacker replacement options, and synchronization on vulnerable and fixed builds.",
  "double-free":
    "Two error paths both release the same allocation after a partial initialization failure; the example traces ownership flags, first free, allocator response, second free, exception behavior, and whether controlled reallocation occurs between them.",
  "reference-counting-bugs":
    "A callback path increments an object reference but one cancellation path decrements twice; the example models every acquire/release edge, concurrent close, underflow or premature destruction, and the patch's ownership transfer.",
  "type-confusion":
    "A handler accepts a generic object handle then interprets the referenced body as the wrong kernel type; the example records handle type checks, expected structure fields, attacker-controlled replacement type, dereference offset, and resulting capability.",
  "uninitialized-memory":
    "A kernel structure is partially filled before being copied to user mode; the example varies allocation history, identifies padding and untouched fields, separates random bytes from pointers or secrets, and validates the fixed zero-initialization path.",
  "null-pointer-dereference":
    "An error path calls through a field of a NULL object; the example checks modern user-page mapping restrictions, fault context, denial-of-service reliability, and whether any build-specific low-address condition creates real control.",
  "race-conditions":
    "Two threads update and consume shared request state without a common lock; the example records the intended happens-before relation, widens the interleaving in a lab, captures both stacks, and tests the fixed synchronization primitive.",
  "toctou-double-fetch":
    "A driver validates a user structure then reads its length or pointer again during use; the example mutates one field between fetches, records which copy each branch observes, and confirms that capturing the structure once removes the inconsistency.",
  "logic-bugs":
    "A state machine permits a sensitive command after an error transition that should have invalidated authorization; the example maps legal states, guard conditions, per-handle state, restart behavior, and the missing transition check.",
  "authorization-bypass":
    "A privileged RPC method checks that a caller is local but not that the caller owns the target object; the example varies token, session, object owner, requested operation, and impersonation to isolate the missing authorization dimension.",
  "acl-misconfiguration":
    "A service, device, or registry object grants an interactive-users group a sensitive object-specific right; the example decodes the ACE mask, inheritance, owner, effective token groups, granted handle rights, and privileged consumer.",
  "path-canonicalization":
    "A privileged service validates a display path but later opens a normalized, device, short-name, or reparse-resolved form; the example compares strings, file IDs, final handles, case behavior, and namespace transitions.",
  "unsafe-protocol-parsing":
    "A private binary request contains nested offsets and lengths that are validated independently but not as ranges within the captured buffer; the example models message version, arithmetic, alignment, state, and unknown-field handling.",
  "weak-cryptographic-gate":
    "A driver accepts commands only after a client supplies a reversible constant-derived response; the example determines whether the exchange proves identity, freshness, possession of a protected secret, or merely protocol compatibility.",
  "arbitrary-read-write-primitives":
    "A memory-corruption bug appears to provide read and write helpers; the example separately measures each direction, address translation, size, value, repetition, failure recovery, and the information required to select a protected target.",
  "ioctl-handlers":
    "A user opens a named device and sends one well-formed IOCTL; the example decodes the control code, device DACL, handle access, transfer method, input/output lengths, requestor mode, dispatch path, backend sink, and completion owner.",
  "irp-create-and-close":
    "A driver authorizes a client during IRP_MJ_CREATE and stores state in a file context; the example tests open rights, share behavior, duplicated handles, cleanup versus close, cancellation, and whether per-file state leaks globally.",
  "filesystem-irps":
    "A minifilter observes a create followed by rename and cleanup; the example records pre/post callbacks, normalized names, stream/file contexts, reparse status, requestor token, recursion, and which layer performs the final file operation.",
  alpc: "A low-privilege client connects to a privileged ALPC port and sends a typed message containing handles; the example maps port security, connection state, message lengths, view/handle attributes, impersonation, and server-side object validation.",
  "shared-memory":
    "A service and client exchange commands through a named section and events; the example records section DACL, view permissions, producer/consumer ownership, sequence numbers, double fetches, bounds, teardown, and stale-client state.",
  "registry-callbacks":
    "A security driver registers a registry callback that rewrites or blocks operations; the example traces altitude order, pre/post information classes, caller context, captured names/data, reentrancy, transaction behavior, and unload cleanup.",
  "ndis-network":
    "A crafted packet reaches a filter or miniport receive path after offload processing; the example records layer, NBL ownership, fragment and length metadata, clone/return lifecycle, cancellation, and whether user-controlled bytes reach the parser.",
  "pnp-and-power":
    "A device receives start, power transition, surprise removal, and remove requests while user I/O remains pending; the example maps queue state, object references, cancellation, hardware mappings, interface enablement, and teardown ordering.",
  "wdf-kmdf":
    "A KMDF queue dispatches a request whose input buffer is retrieved through a framework helper; the example follows device-init security, queue type, execution level, synchronization scope, request ownership, cancellation, and object parenting.",
  "wmi-etw":
    "A provider accepts WMI method input or emits ETW events containing kernel-derived data; the example maps registration, provider security, schemas, buffer lengths, consumer access, enable/disable races, and pointer scrubbing.",
  clfs: "A user-controlled log file drives CLFS container parsing and metadata updates; the example pins the file format and build, traces offsets through validation to pool operations, and separates the root cause from any later kernel primitive.",
  ntfs: "A crafted filesystem object or metadata operation reaches NTFS through ordinary file APIs; the example records volume format, oplocks, reparses, transactions, cache state, IRP path, parser assumptions, and reboot-stable reproduction.",
  afd: "A Winsock operation reaches AFD through an internal IOCTL and asynchronous endpoint state; the example maps socket API to AFD request, user buffers, endpoint ownership, completion, cancellation, and the exact missing validation.",
  "win32k-attack-surface":
    "A GUI process creates and mutates USER or GDI objects that cross into win32k; the example pins session/desktop state, syscall path, handle-table object type, callback behavior, lifetime, and applicable isolation mitigations.",
  "io-ring-attack-surface":
    "A process creates an I/O ring, registers buffers and files, then submits chained operations; the example maps object security, registration tables, submission validation, asynchronous completion, cancellation, and build-specific structure state.",
  "wnf-attack-surface":
    "A process publishes and subscribes to WNF state across a chosen scope; the example records state-name encoding, scope permissions, data lifetime, subscription callbacks, size transitions, and teardown races.",
  "filesystem-namespace-surface":
    "A privileged process resolves a path that crosses DOS devices, Object Manager links, NTFS reparses, and mount points; the example records identity at each hop and compares validated versus finally opened file IDs.",
  "service-control-manager":
    "A standard user opens the SCM and a service with read-only rights; the example decodes both object DACLs, granted handles, configuration, start/stop controls, service account, trigger state, and referenced files or DLLs.",
  "rpc-services":
    "A client discovers and binds to a privileged RPC interface then calls a benign method; the example maps endpoint ACL, authentication service/level, interface UUID, opnum, context handles, impersonation, and backend object authorization.",
  "com-activation":
    "A client activates an out-of-process COM class registered to a privileged local server; the example follows CLSID/AppID lookup, registry view, launch/access permissions, elevation policy, marshaling, client token, and server-side authorization.",
  "named-pipe-surface":
    "A service creates a named pipe and accepts multiple clients; the example records pipe DACL, instance flags, remote-client policy, client PID/token queries, impersonation level, message framing, disconnect, and instance reuse.",
  "installer-updater-surface":
    "A privileged updater consumes a downloaded package and stages files before replacement; the example maps signature and manifest validation, staging ACLs, temporary names, junction/reparse policy, rollback, service restart, and cleanup.",
  "process-thread-token-surface":
    "A privileged broker opens a caller-selected process or thread and returns information or a duplicated handle; the example records target identity, requested/granted rights, PPL state, token context, PID reuse, and object-reference timing.",
  "core-kernel":
    "A kernel executive path manages process, token, object, memory, or synchronization state reached through a system call; the example uses matching symbols to trace object references, locks, requestor context, and the smallest caller-controlled transition.",
  "filesystem-drivers":
    "A filesystem driver parses on-disk metadata and services concurrent cached and noncached I/O; the example records volume state, IRP paths, names, streams, oplocks, transactions, cache manager interaction, and teardown.",
  "minifilter-drivers":
    "A minifilter intercepts create and write operations at a specific altitude; the example maps registration, pre/post callbacks, contexts, normalized names, impersonation, pended work, recursion controls, unload, and communication ports.",
  "log-transaction-drivers":
    "A logging or transaction driver parses persistent records and replays state after interruption; the example studies record bounds, restart areas, sequence numbers, transaction ownership, crash recovery, concurrent access, and rollback.",
  "kernel-streaming-drivers":
    "A user builds a graph of kernel-streaming filters, pins, and property requests; the example maps topology, automation tables, variable property buffers, object lifetime, asynchronous streaming, and third-party mini-driver delegation.",
  "network-stack-drivers":
    "A packet crosses WFP, NDIS filters, protocol, and transport state before completion; the example records the exact layer, ownership and clone rules, offloads, fragments, asynchronous callbacks, cancellation, and user-reachable configuration.",
  "storage-caching-drivers":
    "A storage filter handles pass-through commands and cached buffers above a virtual or physical device; the example traces IOCTL/SRB validation, sector arithmetic, MDLs, DMA mappings, completion, removal, and management permissions.",
  "security-policy-drivers":
    "An endpoint-security driver registers process, thread, image, registry, and object callbacks while exposing a management channel; the example compares callback authority, allowlist policy, protected state, client DACL, update path, and unload controls.",
  "third-party-security-drivers":
    "A security product combines a kernel sensor with a SYSTEM service and updater; the example maps trust across device IOCTLs, shared memory, callbacks, cloud policy, exclusions, self-protection, signatures, and compatibility fallbacks.",
  "vendor-utility-drivers":
    "A motherboard or tuning utility exposes physical memory, MSR, port, PCI, or firmware operations; the example maps device security and private gates to each backend primitive, then records deployment, block-policy, and load prerequisites.",
  "performance-and-gpu-drivers":
    "A graphics or performance driver accepts complex command buffers and memory-management requests; the example maps user queues, GPU virtual memory, shared allocations, synchronization, firmware interfaces, reset, and cross-process isolation.",
  "win32k-subsystem":
    "A GUI syscall manipulates session-scoped USER/GDI objects and may invoke user-mode callbacks; the example records object handle types, desktop/window-station security, callback reentrancy, locking, lifetime, and modern isolation boundaries.",
  "wdm-wdf-driver-models":
    "The same device operation is compared in raw WDM and KMDF implementations; the example identifies who owns IRPs/requests, buffers, queues, cancellation, synchronization, object lifetime, PnP/power transitions, and device security.",
  "service-security":
    "A standard user inventories one SYSTEM service and its SCM object; the example separates SCM rights from service rights, decodes the DACL, records the service account and configuration, and traces which referenced objects the service consumes.",
  "weak-service-dacl":
    "A service DACL grants a nonadmin group SERVICE_CHANGE_CONFIG on a lab service; the example verifies the granted handle mask, changes no production state, and explains how binary-path control would compose with service start under the service account.",
  "service-binary-path":
    "A lab service runs as LocalSystem and its ImagePath or executable is modifiable by a standard user; the example distinguishes service-object configuration rights, registry/file rights, command-line parsing, environment expansion, and restart authority.",
  "unquoted-service-path":
    "A service command line contains spaces without quotes; the example enumerates each executable candidate Windows would try, then checks whether the standard user can create that candidate and whether the real service parser is vulnerable.",
  "service-dll-loading":
    "A privileged service loads a plugin by relative name or from a writable directory; the example captures the loader search order, SafeDllSearchMode, known DLLs, manifests, current directory, architecture, signatures, and restart trigger.",
  "service-registry-permissions":
    "A service reads plugin, command, account, or policy values from a key writable by ordinary users; the example decodes WOW64 view and value type, traces the privileged read, and proves which change affects a sensitive operation.",
  "service-failure-actions":
    "A lab service allows a standard user to configure or trigger failure actions; the example separates SERVICE_CHANGE_CONFIG, crash/stop rights, recovery command behavior, reset period, service account, and whether commands are actually supported.",
  "service-control-abuse":
    "A user can start, stop, pause, or send custom controls to a privileged service; the example decodes each granted control right and traces whether any handler performs a sensitive action without additional caller authorization.",
  "weak-device-dacl":
    "A kernel device grants Everyone read/write access while exposing privileged IOCTLs; the example opens the handle as a standard user, records granted rights, decodes IOCTL access bits, and traces operation-specific authorization.",
  "token-impersonation":
    "A server thread impersonates a connected client then performs local resource access; the example records token type, impersonation level, dynamic/static tracking, effective-only behavior, revert paths, and the final principal used.",
  "named-pipe-impersonation":
    "A named-pipe server causes a privileged client to connect and write before impersonating it; the example checks pipe DACL, client identity, SQOS, impersonation level, first-message requirement, thread token, and safe reversion.",
  "seimpersonate-privilege":
    "A service account owns SeImpersonatePrivilege and controls a server endpoint; the example explains why the privilege alone is insufficient, then maps the required privileged client connection, impersonation token level, process creation path, and mitigations.",
  "handle-acquisition":
    "A low-privilege process obtains or duplicates a handle to a stronger process, token, service, or file; the example records source handle owner, granted rights, inheritance/duplication path, PPL restrictions, and the exact operation enabled.",
  "com-hijacking":
    "A privileged process activates a CLSID whose registration resolution includes a user-writable location; the example traces registry precedence and view, class context, server type, AppID security, caller integrity, and the actual privileged activation.",
  "dll-hijacking":
    "A privileged executable requests a DLL without a protected absolute path; the example captures the exact search order, process current directory, KnownDLLs, manifests, architecture, writable candidates, signature policy, and load evidence.",
  "scheduled-task-abuse":
    "A scheduled task runs as SYSTEM but exposes a modifiable action, file, directory, or task security descriptor; the example separates task-object rights, XML/registry storage, executable path rights, trigger conditions, and run-level behavior.",
  "installer-rollback":
    "A privileged installer stages and later restores files after a forced failure; the example maps transaction or rollback metadata, staging ACLs, file identity, reparse protections, failure timing, privileged write, and cleanup.",
  "privileged-file-operations":
    "A SYSTEM service offers copy, move, delete, extract, or restore functionality; the example traces impersonation, canonical handles, reparse policy, destination rights, overwrite semantics, archive traversal, and the privileged consumer after the operation.",
  "rpc-com-confused-deputy":
    "A privileged RPC or COM server accepts an object name from a lower-trust client and opens it after reverting impersonation; the example records authentication, client token, object ownership, revert point, backend access, and missing policy check.",
  "registry-autorun-and-provider-loading":
    "A privileged process consumes an autorun, provider, plugin, or handler registration from a location writable by a weaker principal; the example resolves registry view, precedence, command parsing, file rights, signatures, and activation trigger.",
  "uac-boundary-model":
    "An administrator with a filtered medium-integrity token triggers an auto-elevated component; the example records linked-token state, consent policy, integrity, elevation moniker or manifest, protected locations, and why the path is not standard-user LPE.",
  "dep-nx":
    "A lab maps a writable page and attempts to treat it as executable under two mitigation states; the example records page protections, image NX compatibility, process policy, exception, and why data-only corruption is outside DEP's scope.",
  kaslr:
    "Two clean boots load the same kernel modules at different virtual addresses; the example records symbol-relative offsets, entropy observations, module query restrictions, and which exploit assumption actually requires an absolute address.",
  "kaslr-bypasses":
    "A chain obtains a kernel pointer through a documented query or information disclosure; the example checks privilege and policy restrictions, pointer usefulness, staleness, target-module identity, and whether the leak defeats only one randomization layer.",
  "smep-smap":
    "A kernel control-flow primitive points toward user memory on systems with and without SMEP/SMAP-like enforcement; the example records CR4/policy state, access type, exception, valid kernel alternatives, and why a data-only path may remain.",
  "kcfg-kcet":
    "An indirect kernel call and return are exercised against control-flow and shadow-stack policy; the example distinguishes valid target metadata, calling convention, return integrity, hardware support, runtime state, and data-only residual paths.",
  "vbs-hvci":
    "Two snapshots differ only in virtualization-based security and memory integrity; the example confirms Device Guard runtime state, code-integrity decisions, executable mapping restrictions, driver compatibility, and the remaining signed-driver surface.",
  kdp: "A kernel write targets a field protected by Kernel Data Protection and a comparable unprotected field; the example records protected-region registration, runtime enforcement, fault behavior, build support, and alternate mutable targets.",
  "pool-hardening":
    "A historical pool-layout technique is repeated on a modern build; the example measures allocator metadata encoding, delayed reuse, cookies, randomization, size classes, processor locality, and which grooming assumptions no longer hold.",
  "secure-pool":
    "A driver allocates sensitive objects from a protected pool policy; the example records allocation API and tag, access restrictions, lifecycle, supported build, fault behavior, and whether unrelated pool objects remain viable targets.",
  acg: "A protected process attempts to create executable code from dynamic memory; the example distinguishes process mitigation policy, allowed image-backed code, trusted broker behavior, thread opt-out, and why kernel data corruption is a different boundary.",
  "driver-signing-code-integrity":
    "A lab compares signed, test-signed, revoked, and policy-blocked drivers; the example records Secure Boot, test mode, WDAC/HVCI, certificate chain, vulnerable-driver blocklist, load status, and why signing does not authorize unsafe IOCTL use.",
  "protected-process-light":
    "A normal administrative process tries to open a PPL target with sensitive rights; the example records signer level, requested/granted access, handle duplication, driver-assisted paths, process protection information, and residual broker interfaces.",
  "why-kernel-drivers":
    "A target-selection exercise compares an internal filter, a widely deployed vendor utility, and a security driver; the example scores exposure, least-privileged reachability, authority, protocol complexity, deployment, update ownership, and realistic impact.",
  "secure-driver-anatomy":
    "A small KMDF control device is reviewed from INF and device SDDL through queue dispatch and cleanup; the example checks least-privilege handles, IOCTL access, per-file authorization, framework buffers, state, cancellation, and telemetry.",
  "exploit-chain-patterns":
    "A writeup begins with a crash and ends with SYSTEM; the example rewrites it as entry point, root cause, measured primitive, missing information, conversion, target, mitigation response, trigger, proof, and cleanup, marking every unproven edge.",
  "mitigation-timeline":
    "A historical exploit technique is tested across several Windows builds; the example pins binary hashes, symbols, structure changes, allocator behavior, mitigation support versus activation, patch level, and the exact release where an assumption changes.",
  "patch-patterns":
    "A fixed driver adds one length check, a reference, and an authorization branch; the example translates each change into a restored invariant and searches sibling handlers for semantically equivalent unpatched paths.",
  "corpus-analytics":
    "Several advisories describe the same driver flaw with different names; the example normalizes hashes, versions, CVEs, root cause, primitive, surface, confidence, provenance, duplicates, and unknown values without inventing missing labels.",
  "kernel-debugging":
    "A debugger session tests one hypothesis about a driver request; the example pins symbols, breaks at dispatch and the suspected invariant transition, scripts object/token state, captures a negative control, and records how instrumentation affects timing.",
  "driver-fuzzing":
    "A stateful IOCTL protocol requires open, initialize, authorize, operate, and cleanup; the example builds a snapshot-reset harness, models request dependencies, adds coverage and verifier signals, minimizes one failure, and deduplicates by root cause.",
  "static-analysis":
    "A review encodes a user-pointer-to-kernel-write flow as a query; the example defines sources, sinks, framework sanitizers, access checks, ownership, unknown calls, vulnerable/fixed tests, and manual triage criteria.",
  "patch-diffing":
    "Two comparable driver builds are matched and one changed handler is decompiled; the example removes compiler noise, identifies the new security decision, proves entry-point reachability, validates versions, and searches alternate paths.",
  byovd:
    "A signed vulnerable driver is evaluated for defensive BYOVD risk; the example separates administrative load prerequisites, existing device access, signing and block policy, protocol gate, reachable primitive, target-build assumptions, and final objective.",
  "symbols-and-structures":
    "A debugger script needs an internal field offset on two Windows builds; the example validates PDB GUID/age, distinguishes public and inferred types, compares versioned references, derives the field when possible, and rejects stale hard-coded offsets.",
  "runtime-tracing":
    "A hidden privileged file operation is correlated across Procmon, ETW, WPR, and debugger events; the example chooses the least invasive provider, records stacks and timestamps, checks dropped events, and accounts for altered race timing.",
  "lab-design":
    "A researcher prepares a reproducible kernel lab; the example records OS and patch state, VM configuration, Secure Boot/HVCI/test signing/verifier, driver hashes, symbols, network isolation, snapshots, reset automation, and host-protection boundaries.",
  "research-evidence":
    "A draft claim says a crash is exploitable; the example separates documented facts, direct observations, debugger evidence, inference, assumptions, negative results, target build, confidence, falsifying tests, and reproduction artifacts.",
  "autopiff-integration":
    "A Patch Tuesday pipeline pairs two driver builds, matches changed functions, decompiles candidates, traces them from IOCTL entry points, classifies restored invariants, ranks confidence separately from severity, and queues manual validation.",
  "kdu-provider-compatibility":
    "A signed driver imports physical-memory routines and is screened as a possible KDU provider; the example expands one provider action into required primitives and confirms reachability and caller control instead of trusting imports.",
  "loldrivers-deep-analysis":
    "A known-driver catalog is enriched with PE metadata and decompiler evidence; the example separates imported, reachable, caller-controlled, and exploitable capabilities while preserving hashes, aliases, signer, mitigations, device security, IOCTLs, and confidence.",
};

const list = (items: string[]) => items.filter(Boolean);

function defaultScenario(concept: HandbookConcept) {
  const firstCapability =
    concept.enables[0]?.toLocaleLowerCase() ?? "the stated capability";
  return `A version-pinned lab reaches ${concept.title} through the least-privileged documented path. The investigation measures whether the observation is sufficient to ${firstCapability}, while keeping the starting identity, object, state, and mitigation assumptions explicit.`;
}

function apiNames(concept: HandbookConcept) {
  return (
    concept.apis?.map((api) => api.name).join(", ") ||
    "the relevant Windows interfaces"
  );
}

const primitiveMemorySlugs = new Set([
  "arbitrary-read",
  "information-leak",
  "arbitrary-write",
  "write-what-where",
  "constrained-write",
  "arbitrary-increment-decrement",
  "bit-manipulation",
  "controlled-dereference",
  "controlled-call-target",
  "pool-overflow-to-read-write",
  "pte-manipulation",
]);

const primitiveTransferSlugs = new Set([
  "direct-ioctl-read-write",
  "dma-mmio-access",
  "mdl-mapping",
  "io-ring",
  "kuser-shared-data",
]);

const primitiveObjectSlugs = new Set([
  "pipe-attribute-primitives",
  "named-pipe-objects",
  "palette-bitmap-objects",
  "pool-spray-feng-shui",
  "wnf-state-data",
]);

const primitiveAuthoritySlugs = new Set([
  "registry-based-primitives",
  "token-manipulation",
  "acl-security-descriptor-manipulation",
  "previous-mode-manipulation",
  "token-swapping",
]);

const primitiveFileSlugs = new Set([
  "arbitrary-file-read",
  "arbitrary-file-create",
  "arbitrary-file-write",
  "arbitrary-file-delete",
  "arbitrary-file-move",
  "arbitrary-directory-create",
  "arbitrary-directory-delete",
  "privileged-file-copy-restore",
]);

const primitiveNamespaceSlugs = new Set([
  "junction-mount-point",
  "object-manager-symbolic-links",
  "hard-link-creation",
  "reparse-point-substitution",
  "oplock-assisted-race",
]);

const memorySafetySlugs = new Set([
  "buffer-overflow",
  "out-of-bounds-read",
  "integer-overflow",
  "uninitialized-memory",
  "null-pointer-dereference",
]);

const lifetimeSlugs = new Set([
  "use-after-free",
  "double-free",
  "reference-counting-bugs",
  "type-confusion",
]);

const concurrencySlugs = new Set(["race-conditions", "toctou-double-fetch"]);

const authorizationSlugs = new Set([
  "logic-bugs",
  "authorization-bypass",
  "acl-misconfiguration",
  "path-canonicalization",
  "unsafe-protocol-parsing",
  "weak-cryptographic-gate",
]);

const driverIoSurfaceSlugs = new Set([
  "ioctl-handlers",
  "irp-create-and-close",
  "wdf-kmdf",
  "io-ring-attack-surface",
]);

const filesystemSurfaceSlugs = new Set([
  "filesystem-irps",
  "clfs",
  "ntfs",
  "filesystem-namespace-surface",
]);

const ipcSurfaceSlugs = new Set([
  "alpc",
  "shared-memory",
  "rpc-services",
  "com-activation",
  "named-pipe-surface",
]);

const callbackSurfaceSlugs = new Set([
  "registry-callbacks",
  "wmi-etw",
  "wnf-attack-surface",
]);

const networkSurfaceSlugs = new Set(["ndis-network", "afd"]);

const serviceConfigurationSlugs = new Set([
  "service-security",
  "weak-service-dacl",
  "service-binary-path",
  "unquoted-service-path",
  "service-dll-loading",
  "service-registry-permissions",
  "service-failure-actions",
  "service-control-abuse",
  "weak-device-dacl",
]);

const tokenLpeSlugs = new Set([
  "token-impersonation",
  "named-pipe-impersonation",
  "seimpersonate-privilege",
  "handle-acquisition",
]);

const loaderLpeSlugs = new Set([
  "com-hijacking",
  "dll-hijacking",
  "registry-autorun-and-provider-loading",
]);

const fileLpeSlugs = new Set([
  "scheduled-task-abuse",
  "installer-rollback",
  "privileged-file-operations",
]);

function makeDemo(
  title: string,
  language: string,
  description: string,
  code: string,
): ConceptDemo {
  return { title, language, description, code };
}

function buildFoundationDemo(
  concept: HandbookConcept,
): ConceptDemo | undefined {
  if (concept.slug === "trust-boundaries") {
    return makeDemo(
      "Capture both sides of the trust boundary",
      "powershell",
      "This read-only snapshot prevents an account name or process label from standing in for the real caller token, service identity, and target object.",
      `$serviceName = 'ExampleService'\n$targetPath = 'C:\\Lab\\target.txt'\n\n[ordered]@{\n  Concept = ${JSON.stringify(concept.title)}\n  Caller = whoami.exe /all\n  Service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" |\n    Select-Object Name, StartName, State, PathName\n  Target = Get-Item -LiteralPath $targetPath -ErrorAction SilentlyContinue |\n    Select-Object FullName, Attributes, Length\n  TargetAcl = Get-Acl -LiteralPath $targetPath -ErrorAction SilentlyContinue\n} | ConvertTo-Json -Depth 6`,
    );
  }

  if (concept.slug === "object-manager-namespaces") {
    return makeDemo(
      "Resolve the name as an Object Manager path",
      "windbg",
      "Use a kernel debugger or WinObj in a disposable VM to distinguish a presentation path, symbolic-link object, device object, and device stack.",
      `; Concept: ${concept.title}\n!object \\GLOBAL??\n!object \\??\n!object \\Device\n\n; Substitute the object address found during read-only enumeration.\n!object <object-address>\n!devobj <device-object>\n!devstack <device-object>\n\n; Record the session, link target, object type, and granted handle rights.`,
    );
  }

  if (concept.slug === "access-checks") {
    return makeDemo(
      "Model an access check explicitly",
      "c",
      "Defensive pseudocode shows the values that must be recorded: caller token, desired mask, object-specific generic mapping, descriptor, and final granted mask.",
      `GENERIC_MAPPING mapping = GetMappingForObjectType(object);\nACCESS_MASK desired = request->DesiredAccess;\nMapGenericMask(&desired, &mapping);\n\nPRIVILEGE_SET privileges = {0};\nDWORD privilegeBytes = sizeof(privileges);\nACCESS_MASK granted = 0;\nBOOL allowed = FALSE;\n\nif (!AccessCheck(object->SecurityDescriptor, caller->ImpersonationToken,\n                 desired, &mapping, &privileges, &privilegeBytes,\n                 &granted, &allowed)) {\n    return GetLastError();\n}\n\n// ${concept.title}: log desired, granted, object type, and token identity.\nreturn allowed ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;`,
    );
  }

  if (concept.slug === "handles-and-access-masks") {
    return makeDemo(
      "Inspect granted rights rather than object names",
      "windbg",
      "The handle-table entry records authority already granted at open time. Compare two handles to the same object whose requested masks differ.",
      `; User-mode WinDbg\n!handle <handle> f\n\n; Kernel WinDbg, scoped to the owning process\n!process <eprocess> 1\n.process /r /p <eprocess>\n!handle <handle> f\n\n; For ${concept.title}, record:\n; object type, object address, GrantedAccess, attributes, owner process,\n; duplication source, and the operation that later consumes the handle.`,
    );
  }

  if (concept.slug === "irp-and-io-stack") {
    return makeDemo(
      "Follow one IRP from dispatch to completion",
      "windbg",
      "These debugger commands turn a generic I/O request into an ownership and lifecycle trace without modifying the target.",
      `!irp <irp-address> 1\n!devstack <device-object>\n!devobj <device-object>\n!thread <request-thread>\n\n; Break at dispatch and completion, then record for ${concept.title}:\n; - current stack location and major/minor function\n; - requestor mode and originating process\n; - buffer representation and owner\n; - pending, cancellation, and completion owner`,
    );
  }

  if (concept.slug === "requestor-mode") {
    return makeDemo(
      "Preserve requestor context across deferred work",
      "c",
      "Defensive pseudocode makes the handoff explicit. A worker must not silently replace an untrusted request with KernelMode assumptions.",
      `typedef struct _WORK_CONTEXT {\n    KPROCESSOR_MODE RequestorMode;\n    PEPROCESS RequestorProcess;\n    ACCESS_MASK DesiredAccess;\n} WORK_CONTEXT;\n\nNTSTATUS QueueRequest(PIRP Irp) {\n    WORK_CONTEXT *ctx = AllocateWorkContext();\n    ctx->RequestorMode = Irp->RequestorMode;\n    ctx->RequestorProcess = IoGetRequestorProcess(Irp);\n    ctx->DesiredAccess = ExtractDesiredAccess(Irp);\n    return QueueValidatedWork(ctx);\n}\n\n// ${concept.title}: the worker must probe/capture user data and force\n// an access check when opening an object on behalf of the requestor.`,
    );
  }

  return undefined;
}

function buildPrimitiveDemo(concept: HandbookConcept): ConceptDemo {
  if (primitiveMemorySlugs.has(concept.slug)) {
    return makeDemo(
      "Measure the memory capability as a contract",
      "python",
      "Populate this matrix from debugger evidence. The assertion deliberately rejects a final-impact claim while any control dimension remains unknown.",
      `from dataclasses import dataclass\n\n@dataclass(frozen=True)\nclass MemoryCapability:\n    concept: str\n    address_space: str\n    target_control: str\n    value_or_disclosure: str\n    width_and_alignment: str\n    repeatability: str\n    prerequisites: tuple[str, ...]\n\ncap = MemoryCapability(\n    concept=${JSON.stringify(concept.title)},\n    address_space="unmeasured",\n    target_control="unmeasured",\n    value_or_disclosure="unmeasured",\n    width_and_alignment="unmeasured",\n    repeatability="unmeasured",\n    prerequisites=("exact build", "sacrificial target", "negative control"),\n)\n\nunknown = [value for value in cap.__dict__.values() if value == "unmeasured"]\nassert not unknown, "Measure every dimension before claiming an arbitrary primitive"`,
    );
  }

  if (primitiveTransferSlugs.has(concept.slug)) {
    return makeDemo(
      "Review the mapping boundary before transfer",
      "c",
      "Defensive pseudocode captures the checks a privileged mapping or transfer interface needs before touching physical, kernel, or registered memory.",
      `NTSTATUS ValidateTransfer(const REQUEST *r, const CALLER *caller) {\n    // Concept under review: ${concept.title}\n    if (!CallerMayUseTransferInterface(caller)) return STATUS_ACCESS_DENIED;\n    if (r->Length == 0 || r->Length > MAX_TRANSFER) return STATUS_INVALID_BUFFER_SIZE;\n    if (AddWouldOverflow(r->Offset, r->Length)) return STATUS_INTEGER_OVERFLOW;\n    if (!RangeBelongsToRegisteredObject(r->Object, r->Offset, r->Length))\n        return STATUS_INVALID_ADDRESS;\n    if (!OperationMatchesGrantedRights(r->Object, r->Operation))\n        return STATUS_ACCESS_DENIED;\n    return STATUS_SUCCESS;\n}\n\n// Retain the referenced object until asynchronous completion and unmap once.`,
    );
  }

  if (primitiveObjectSlugs.has(concept.slug)) {
    return makeDemo(
      "Track object identity and lifetime in the debugger",
      "windbg",
      "Record object type, ownership, allocation state, reference counts, and the exact field controlled by the measured capability.",
      `; Concept: ${concept.title}\n!object <object-address>\n!pool <allocation-address>\n!poolval <allocation-address>\ndq <allocation-address> L20\n\n; Add type-specific inspection when symbols permit:\ndt nt!_OBJECT_HEADER <header-address>\n\n; Compare a clean object and the test object. Do not infer control from\n; allocator adjacency alone; prove the changed field independently.`,
    );
  }

  if (primitiveAuthoritySlugs.has(concept.slug)) {
    return makeDemo(
      "Record authority before and after the transition",
      "powershell",
      "This read-only evidence bundle separates token identity, privileges, integrity, and ACL state from the operation that allegedly changes authority.",
      `$targetPath = 'C:\\Lab\\target.txt'\n\n$before = [ordered]@{\n  Concept = ${JSON.stringify(concept.title)}\n  Identity = whoami.exe /all\n  Privileges = whoami.exe /priv\n  TargetAcl = Get-Acl -LiteralPath $targetPath -ErrorAction SilentlyContinue\n}\n\n$before | ConvertTo-Json -Depth 6\n\n# Capture the same fields after the isolated test and diff individual rights.\n# A changed username string is not proof of a changed token or granted access.`,
    );
  }

  if (primitiveFileSlugs.has(concept.slug)) {
    return makeDemo(
      "Pin the file object and privileged consumer",
      "powershell",
      "The snippet performs no create, write, move, or delete. It records canonical path, identity, link metadata, and ACLs needed to reason about the file primitive safely.",
      `$inputPath = 'C:\\Lab\\candidate'\n+$fullPath = [System.IO.Path]::GetFullPath($inputPath)\n+$item = Get-Item -LiteralPath $fullPath -Force -ErrorAction SilentlyContinue\n\n[ordered]@{\n  Concept = ${JSON.stringify(concept.title)}\n  InputPath = $inputPath\n  FullPath = $fullPath\n  Exists = Test-Path -LiteralPath $fullPath\n  Item = $item | Select-Object FullName, LinkType, Target, Attributes\n  ParentAcl = Get-Acl -LiteralPath (Split-Path $fullPath -Parent)\n  Caller = whoami.exe /all\n} | ConvertTo-Json -Depth 6\n\n# Next, trace which stronger principal resolves and consumes this exact path.`,
    );
  }

  if (primitiveNamespaceSlugs.has(concept.slug)) {
    return makeDemo(
      "Observe name resolution without changing the namespace",
      "powershell",
      "Use an existing disposable test path. The commands reveal filesystem link metadata and reparse information; they do not create or retarget links.",
      `$path = 'C:\\Lab\\existing-link'\n+$item = Get-Item -LiteralPath $path -Force -ErrorAction Stop\n\n$item | Select-Object FullName, LinkType, Target, Attributes\n+Get-Acl -LiteralPath $path | Format-List Owner, AccessToString\n+fsutil.exe reparsepoint query $path\n\n# Concept: ${concept.title}\n# Record the name checked, the object opened, the handle retained, and whether\n# an oplock or namespace change can occur between validation and use.`,
    );
  }

  return makeDemo(
    "Record the primitive before choosing a target",
    "python",
    "This analysis scaffold forces a researcher to record control and constraints before using the word arbitrary or claiming a final impact.",
    `from dataclasses import dataclass\n\n@dataclass(frozen=True)\nclass Primitive:\n    name: str\n    target_control: str\n    value_control: str\n    width: str\n    repeatable: bool\n    preconditions: tuple[str, ...]\n\np = Primitive(\n    name=${JSON.stringify(concept.title)},\n    target_control="unmeasured",\n    value_control="unmeasured",\n    width="unmeasured",\n    repeatable=False,\n    preconditions=("pin build", "record caller token", "use sacrificial target"),\n)\n\nassert "unmeasured" not in (p.target_control, p.value_control, p.width), (\n    "Do not claim an arbitrary primitive until every control dimension is measured"\n)`,
  );
}

function buildVulnerabilityDemo(concept: HandbookConcept): ConceptDemo {
  if (memorySafetySlugs.has(concept.slug)) {
    return makeDemo(
      "Make bounds and initialization reviewable",
      "c",
      "The example keeps overflow-safe arithmetic, initialization, validation, and use adjacent. Replace the placeholders with the actual WDM or WDF buffer contract.",
      `NTSTATUS ParseRecord(const uint8_t *buffer, size_t bufferLength) {\n    // Vulnerability class: ${concept.title}\n    if (buffer == NULL) return STATUS_INVALID_PARAMETER;\n    if (bufferLength < sizeof(RECORD_HEADER)) return STATUS_BUFFER_TOO_SMALL;\n\n    const RECORD_HEADER *header = (const RECORD_HEADER *)buffer;\n    size_t total = 0;\n    if (!SafeSizeAdd(sizeof(*header), header->PayloadLength, &total))\n        return STATUS_INTEGER_OVERFLOW;\n    if (total > bufferLength || total > MAX_RECORD_SIZE)\n        return STATUS_INVALID_BUFFER_SIZE;\n\n    PARSED_RECORD result = {0};\n    return ParseBoundedPayload(buffer + sizeof(*header), header->PayloadLength,\n                               &result);\n}`,
    );
  }

  if (lifetimeSlugs.has(concept.slug)) {
    return makeDemo(
      "Pair ownership with the asynchronous lifetime",
      "c",
      "Defensive pseudocode shows a reference being acquired under synchronization, transferred to queued work, and released exactly once during completion.",
      `NTSTATUS QueueObjectWork(OBJECT_CONTEXT *ctx) {\n    // Vulnerability class: ${concept.title}\n    AcquireLock(&ctx->Lock);\n    if (ctx->State != ObjectReady || !TryAcquireReference(ctx->Object)) {\n        ReleaseLock(&ctx->Lock);\n        return STATUS_DELETE_PENDING;\n    }\n    ctx->OutstandingWork++;\n    ReleaseLock(&ctx->Lock);\n\n    NTSTATUS status = QueueWorkItem(ctx->Object);\n    if (!NT_SUCCESS(status)) CompleteObjectWork(ctx, ctx->Object);\n    return status;\n}\n\nvoid CompleteObjectWork(OBJECT_CONTEXT *ctx, OBJECT *object) {\n    ReleaseReference(object);\n    DecrementOutstandingWorkAndSignalIfZero(ctx);\n}`,
    );
  }

  if (concurrencySlugs.has(concept.slug)) {
    return makeDemo(
      "Capture mutable input once and validate the captured state",
      "c",
      "The important property is that authorization and use operate on the same immutable snapshot, with object identity retained across asynchronous work.",
      `NTSTATUS CaptureAndUse(const USER_REQUEST *userRequest, CALLER *caller) {\n    REQUEST_SNAPSHOT snapshot = {0};\n    NTSTATUS status = CaptureUserRequestOnce(userRequest, &snapshot);\n    if (!NT_SUCCESS(status)) return status;\n\n    if (!ValidateSnapshot(&snapshot)) return STATUS_INVALID_PARAMETER;\n    if (!AuthorizeSnapshot(caller, &snapshot)) return STATUS_ACCESS_DENIED;\n\n    REFERENCED_OBJECT *object = ReferenceObjectByStableIdentity(&snapshot);\n    if (object == NULL) return STATUS_OBJECT_NAME_NOT_FOUND;\n\n    // ${concept.title}: do not reread userRequest or resolve a mutable name here.\n    status = PerformOperation(object, &snapshot);\n    DereferenceObject(object);\n    return status;\n}`,
    );
  }

  if (authorizationSlugs.has(concept.slug)) {
    return makeDemo(
      "Authorize the canonical object and exact operation",
      "c",
      "This defensive flow resists path, protocol, ACL, and confused-deputy mistakes by separating parsing, canonicalization, object lookup, and object-specific authorization.",
      `NTSTATUS DispatchPrivilegedOperation(const MESSAGE *wire, CALLER *caller) {\n    CAPTURED_MESSAGE message = {0};\n    if (!ParseVersionedMessage(wire, &message)) return STATUS_INVALID_PARAMETER;\n    if (!VerifyAuthenticatedState(caller, &message)) return STATUS_ACCESS_DENIED;\n\n    CANONICAL_IDENTITY identity = {0};\n    if (!CanonicalizeTarget(&message, &identity)) return STATUS_OBJECT_PATH_INVALID;\n\n    REFERENCED_OBJECT *target = ReferenceExpectedObjectType(&identity);\n    if (target == NULL) return STATUS_OBJECT_TYPE_MISMATCH;\n\n    // Class under review: ${concept.title}\n    NTSTATUS status = AuthorizeExactOperation(caller, target, message.Operation);\n    if (NT_SUCCESS(status)) status = PerformBoundedOperation(target, &message);\n    DereferenceObject(target);\n    return status;\n}`,
    );
  }

  return makeDemo(
    "Separate corruption from the resulting primitive",
    "python",
    "Use the record to keep the root-cause invariant, first invalid transition, crash, measured control, and final impact as distinct evidence-backed claims.",
    `finding = {\n    "class": ${JSON.stringify(concept.title)},\n    "expected_invariant": "write the property that must remain true",\n    "first_invalid_transition": "break before the crash and record it",\n    "faulting_symptom": "exception, status, or corrupted object",\n    "measured_primitive": "unknown until independently demonstrated",\n    "mitigations": ["record active runtime state"],\n    "negative_control": "one change that preserves the invariant",\n}\n\nassert finding["first_invalid_transition"] != finding["faulting_symptom"]`,
  );
}

function buildAttackSurfaceDemo(concept: HandbookConcept): ConceptDemo {
  if (driverIoSurfaceSlugs.has(concept.slug)) {
    return makeDemo(
      "Map a device request to its handler",
      "powershell",
      "Begin with a read-only driver inventory, then annotate device security, granted handle rights, buffer method, dispatch routine, and backend sink in the lab notebook.",
      `$driverName = 'ExampleDriver'\n\nGet-CimInstance Win32_SystemDriver -Filter "Name='$driverName'" |\n  Select-Object Name, State, StartMode, PathName\n\nsc.exe qc $driverName\nGet-AuthenticodeSignature 'C:\\Windows\\System32\\drivers\\example.sys' |\n  Select-Object Status, SignerCertificate\n\n# Surface: ${concept.title}\n# Decode each IOCTL into DeviceType, Function, Method, and Access.\n# Prove the least-privileged caller can open the device before handler analysis.`,
    );
  }

  if (filesystemSurfaceSlugs.has(concept.slug)) {
    return makeDemo(
      "Record the filesystem stack and namespace state",
      "powershell",
      "These non-mutating commands capture volume, filter, path, link, and ACL context before tracing one request through the filesystem stack.",
      `$path = 'C:\\Lab\\sample.bin'\n\nfltmc.exe filters\nfltmc.exe instances\nfsutil.exe fsinfo volumeinfo (Split-Path -Qualifier $path)\nGet-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue |\n  Select-Object FullName, Attributes, LinkType, Target, Length\nGet-Acl -LiteralPath $path -ErrorAction SilentlyContinue | Format-List\n\n# Surface: ${concept.title}\n# Record IRP major/minor function, reparse result, oplock/cache state, and owner.`,
    );
  }

  if (ipcSurfaceSlugs.has(concept.slug)) {
    return makeDemo(
      "Inventory the IPC endpoint and caller context",
      "powershell",
      "The endpoint name is only a lead. Preserve server identity, endpoint ACL, authentication or impersonation level, protocol state, and the operation that reaches a privileged sink.",
      `$snapshot = [ordered]@{\n  Surface = ${JSON.stringify(concept.title)}\n  Caller = whoami.exe /all\n  NamedPipes = Get-ChildItem -LiteralPath '\\\\.\\pipe\\' -ErrorAction SilentlyContinue |\n    Select-Object -First 50 Name\n  Services = Get-CimInstance Win32_Service |\n    Select-Object Name, StartName, State, PathName\n}\n\n$snapshot | ConvertTo-Json -Depth 6\n\n# Add endpoint-specific ACL and protocol observations from the disposable lab.\n# A connectable endpoint is not proof that a sensitive method is authorized.`,
    );
  }

  if (callbackSurfaceSlugs.has(concept.slug)) {
    return makeDemo(
      "Correlate registration with callback execution",
      "powershell",
      "Collect providers and loaded drivers first, then use build-pinned tracing to prove which registration receives attacker-influenced state.",
      `Get-CimInstance Win32_SystemDriver |\n  Where-Object State -eq 'Running' |\n  Select-Object Name, PathName | Sort-Object Name\n\nlogman.exe query providers | Select-String -Pattern 'Kernel|Registry|WNF|WMI'\n\n# Surface: ${concept.title}\n# Record registration API, altitude/order, callback context, operation class,\n# captured input, reentrancy behavior, teardown, and final privileged side effect.`,
    );
  }

  if (networkSurfaceSlugs.has(concept.slug)) {
    return makeDemo(
      "Pin network state before tracing the kernel path",
      "powershell",
      "This inventory captures adapters, bindings, sockets, and driver state. The next step is a single well-formed packet or socket operation with tracing and a negative control.",
      `Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, DriverVersion\nGet-NetAdapterBinding | Where-Object Enabled |\n  Select-Object Name, DisplayName, ComponentID\nGet-NetTCPConnection -ErrorAction SilentlyContinue |\n  Select-Object -First 30 State, LocalAddress, LocalPort, OwningProcess\n\n# Surface: ${concept.title}\n# Correlate API -> request/packet -> endpoint/adapter state -> completion/cancel.`,
    );
  }

  if (concept.slug === "pnp-and-power") {
    return makeDemo(
      "Capture the device lifecycle before testing transitions",
      "powershell",
      "Enumerate device and driver state without disabling or removing anything. Lifecycle tests belong in a snapshot because surprise removal and power transitions can destabilize the VM.",
      `pnputil.exe /enum-devices /connected /drivers\nGet-PnpDevice -PresentOnly | Select-Object Class, FriendlyName, Status, InstanceId\nGet-CimInstance Win32_SystemDriver | Select-Object Name, State, StartMode, PathName\n\n# Surface: ${concept.title}\n# Later trace START, STOP, QUERY_REMOVE, SURPRISE_REMOVAL, D0/D3, cancellation,\n# and teardown while retaining exact object and request ownership.`,
    );
  }

  return makeDemo(
    "Build an endpoint-to-sink ledger",
    "python",
    "A surface is not a module name. Fill one row per operation so reachability, parsing, authorization, state, lifetime, and final authority remain independently reviewable.",
    `surface = {\n    "name": ${JSON.stringify(concept.title)},\n    "endpoint": "record exact endpoint",\n    "least_privileged_caller": "record token and session",\n    "operation_id": "record method, message, IOCTL, or callback class",\n    "activation_state": "record required service, device, or policy",\n    "input_capture": "record buffer and ownership model",\n    "authorization": "record check and granted rights",\n    "privileged_sink": "record final operation",\n    "negative_control": "record expected rejection",\n}\n\nassert all(value != "" for value in surface.values())`,
  );
}

function buildDriverTypeDemo(concept: HandbookConcept): ConceptDemo {
  if (
    [
      "filesystem-drivers",
      "minifilter-drivers",
      "log-transaction-drivers",
      "storage-caching-drivers",
    ].includes(concept.slug)
  ) {
    return makeDemo(
      "Map the filesystem driver deployment unit",
      "powershell",
      "The image alone is incomplete. Record filters, instances, volumes, service configuration, signer, and the file operations the driver observes or performs.",
      `fltmc.exe filters\nfltmc.exe instances\nGet-Volume | Select-Object DriveLetter, FileSystem, FileSystemLabel, HealthStatus\nGet-CimInstance Win32_SystemDriver |\n  Where-Object { $_.PathName -match '\\.sys' } |\n  Select-Object Name, State, StartMode, PathName\n\n# Driver family: ${concept.title}\n# Add INF/service DACL, altitude or stack position, callbacks/major functions,\n# reparse behavior, recursive I/O handling, cancellation, and unload evidence.`,
    );
  }

  if (concept.slug === "network-stack-drivers") {
    return makeDemo(
      "Inventory NDIS and network filter relationships",
      "powershell",
      "Capture adapter and binding state before tracing packet, offload, OID, pause, restart, cancellation, and completion lifecycles.",
      `Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, DriverVersion\nGet-NetAdapterBinding | Sort-Object Name, ComponentID |\n  Select-Object Name, Enabled, DisplayName, ComponentID\nGet-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue |\n  Select-Object Name, DisplayName, DisplayValue\n\n# Driver family: ${concept.title}\n# Map NDIS role, attach order, control device, IOCTLs, OIDs, and packet ownership.`,
    );
  }

  if (
    [
      "security-policy-drivers",
      "third-party-security-drivers",
      "vendor-utility-drivers",
    ].includes(concept.slug)
  ) {
    return makeDemo(
      "Inventory policy, companion services, and exposed authority",
      "powershell",
      "A security or utility driver must be reviewed with its INF, service, device interface, companion processes, update path, signer, and backend operations.",
      `$driverPath = 'C:\\Windows\\System32\\drivers\\example.sys'\n\nGet-AuthenticodeSignature -FilePath $driverPath |\n  Select-Object Status, StatusMessage, SignerCertificate\nGet-FileHash -Algorithm SHA256 -LiteralPath $driverPath\nGet-CimInstance Win32_SystemDriver |\n  Select-Object Name, State, StartMode, PathName | Sort-Object Name\nGet-CimInstance Win32_Service |\n  Select-Object Name, StartName, State, PathName | Sort-Object Name\n\n# Driver family: ${concept.title}\n# Prove device DACL and handler reachability before scoring dangerous imports.`,
    );
  }

  if (concept.slug === "performance-and-gpu-drivers") {
    return makeDemo(
      "Capture GPU and display driver context",
      "powershell",
      "Record user-mode and kernel components, versions, hardware identity, services, and active mitigations before tracing submission, mapping, escape, and reset paths.",
      `Get-CimInstance Win32_VideoController |\n  Select-Object Name, PNPDeviceID, DriverVersion, DriverDate, AdapterCompatibility\nGet-PnpDevice -Class Display | Select-Object FriendlyName, Status, InstanceId\nGet-CimInstance Win32_SystemDriver |\n  Where-Object { $_.Name -match 'display|gpu|video' -or $_.PathName -match 'display|gpu' } |\n  Select-Object Name, State, PathName\n\n# Driver family: ${concept.title}\n# Map user client -> runtime -> escape/submission -> mapping -> completion/reset.`,
    );
  }

  if (concept.slug === "wdm-wdf-driver-models") {
    return makeDemo(
      "Identify framework ownership before auditing callbacks",
      "windbg",
      "Framework-managed queues, buffers, cancellation, and object parenting change the correct review model; record WDM/WDF boundaries before applying lifecycle assumptions.",
      `lm m <driver-module>\n!drvobj <driver-object> 7\n!devstack <device-object>\n!wdfkd.wdfdriverinfo <wdf-driver-globals>\n!wdfkd.wdfdevice <wdf-device>\n!wdfkd.wdfqueue <wdf-queue>\n\n; Driver family: ${concept.title}\n; Record framework version, queue dispatch mode, synchronization scope,\n; request buffer access, cancellation owner, object parents, and teardown order.`,
    );
  }

  return makeDemo(
    "Build a driver-family inventory",
    "powershell",
    "Start with load state, service configuration, image hash, and signer. Then add family-specific endpoints, callbacks, privileged resources, and lifecycle transitions.",
    `$driverPath = 'C:\\Windows\\System32\\drivers\\example.sys'\n\n[ordered]@{\n  Family = ${JSON.stringify(concept.title)}\n  Drivers = Get-CimInstance Win32_SystemDriver |\n    Select-Object Name, State, StartMode, PathName\n  Signature = Get-AuthenticodeSignature -FilePath $driverPath\n  Hash = Get-FileHash -Algorithm SHA256 -LiteralPath $driverPath\n} | ConvertTo-Json -Depth 6\n\n# Relevant interfaces: ${apiNames(concept)}\n# Add device stack, endpoint DACL, operations, PnP/power, update, and unload.`,
  );
}

function buildLpeDemo(concept: HandbookConcept): ConceptDemo {
  if (serviceConfigurationSlugs.has(concept.slug)) {
    return makeDemo(
      "Audit one service without mutating it",
      "powershell",
      "This evidence bundle separates service-object rights, registry/file permissions, account identity, parsing, and restart authority instead of calling every writable artifact exploitable.",
      `$serviceName = 'ExampleService'\n$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"\n\n$service | Select-Object Name, StartName, State, StartMode, PathName\nsc.exe qc $serviceName\nsc.exe sdshow $serviceName\n\nif ($service.PathName) {\n  $service.PathName\n  # Resolve the executable and arguments manually before checking each parent ACL.\n}\n\n# LPE concept: ${concept.title}\n# Record SERVICE_CHANGE_CONFIG/WRITE_DAC/START/STOP separately and prove which\n# stronger account consumes any writable configuration after a reachable trigger.`,
    );
  }

  if (tokenLpeSlugs.has(concept.slug)) {
    return makeDemo(
      "Record token and IPC prerequisites",
      "powershell",
      "The commands are read-only. They establish caller privileges, integrity, group state, process/service identities, and visible pipe names before any impersonation claim is tested.",
      `[ordered]@{\n  Concept = ${JSON.stringify(concept.title)}\n  Caller = whoami.exe /all\n  Privileges = whoami.exe /priv\n  Processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue |\n    Select-Object -First 50 Id, ProcessName, UserName\n  Pipes = Get-ChildItem -LiteralPath '\\\\.\\pipe\\' -ErrorAction SilentlyContinue |\n    Select-Object -First 50 Name\n} | ConvertTo-Json -Depth 6\n\n# Then prove connection direction, impersonation level, SQOS, token type,\n# granted process/thread rights, privilege enablement, and the final action.`,
    );
  }

  if (loaderLpeSlugs.has(concept.slug)) {
    return makeDemo(
      "Map loader inputs and write permissions",
      "powershell",
      "This read-only survey records the registration or search input, resolved artifacts, and ACLs. A writable key or directory becomes impact only when a stronger reachable consumer loads from it.",
      `$paths = @(\n  'HKCU:\\Software\\Classes',\n  'HKLM:\\Software\\Classes',\n  'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows',\n  'C:\\Lab'\n)\n\nforeach ($path in $paths) {\n  [ordered]@{\n    Concept = ${JSON.stringify(concept.title)}\n    Path = $path\n    Exists = Test-Path -LiteralPath $path\n    Acl = Get-Acl -LiteralPath $path -ErrorAction SilentlyContinue\n  }\n}\n\n# Add Process Monitor or loader-snap evidence for the exact privileged consumer,\n# activation trigger, search order, missing candidate, architecture, and signature policy.`,
    );
  }

  if (fileLpeSlugs.has(concept.slug)) {
    return makeDemo(
      "Trace the privileged file consumer",
      "powershell",
      "The example inventories scheduled tasks and target ACLs without starting tasks, installers, or file operations. Final impact requires a stronger consumer and a repeatable trigger.",
      `$target = 'C:\\Lab\\candidate'\n\nGet-ScheduledTask | ForEach-Object {\n  [pscustomobject]@{\n    TaskPath = $_.TaskPath\n    TaskName = $_.TaskName\n    Principal = $_.Principal.UserId\n    RunLevel = $_.Principal.RunLevel\n    Actions = ($_.Actions | ConvertTo-Json -Compress)\n  }\n} | Select-Object -First 100\n\nGet-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue |\n  Select-Object FullName, LinkType, Target, Attributes\nGet-Acl -LiteralPath $target -ErrorAction SilentlyContinue | Format-List\n\n# LPE concept: ${concept.title}; record resolution, identity, timing, and trigger.`,
    );
  }

  if (concept.slug === "rpc-com-confused-deputy") {
    return makeDemo(
      "Bind each RPC method to caller and target authorization",
      "python",
      "Use one ledger row per RPC or COM method. Authentication to the server and authorization for the backend object are different claims.",
      `method = {\n    "concept": ${JSON.stringify(concept.title)},\n    "endpoint_or_clsid": "record exact identity",\n    "server_principal": "record process token",\n    "client_principal": "record authenticated caller",\n    "authn_level": "record negotiated level",\n    "impersonation_level": "record actual level",\n    "method": "record opnum or interface method",\n    "target_object": "record canonical backend identity",\n    "required_right": "record object-specific authorization",\n    "side_effect": "record independent observation",\n}\n\nassert method["client_principal"] != method["server_principal"]`,
    );
  }

  return makeDemo(
    "Model the privilege transition as separate edges",
    "python",
    "This chain model refuses to collapse influence, consumption, execution identity, and final impact into the phrase local privilege escalation.",
    `chain = {\n    "concept": ${JSON.stringify(concept.title)},\n    "starting_identity": "record token, integrity, privileges, session",\n    "attacker_control": "record exact writable field/object/path",\n    "privileged_consumer": "record process/service and token",\n    "trigger": "record who can invoke it and when",\n    "final_action": "record exact protected operation",\n    "negative_control": "remove one edge and confirm failure",\n}\n\nassert all("record" in value for key, value in chain.items() if key != "concept")`,
  );
}

function buildMitigationDemo(concept: HandbookConcept): ConceptDemo {
  if (
    ["dep-nx", "acg", "kcfg-kcet", "protected-process-light"].includes(
      concept.slug,
    )
  ) {
    return makeDemo(
      "Compare system and process mitigation state",
      "powershell",
      "Policy support is not the same as configuration or enforcement. Capture system defaults and the exact target process, then confirm behavior with a negative control.",
      `$processName = 'notepad.exe'\n\n[ordered]@{\n  Mitigation = ${JSON.stringify(concept.title)}\n  Build = [System.Environment]::OSVersion.VersionString\n  System = Get-ProcessMitigation -System\n  Target = Get-ProcessMitigation -Name $processName -ErrorAction SilentlyContinue\n  Running = Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($processName)) ` +
        `-ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path\n}\n\n# Confirm effective behavior in the exact process; registry or policy output alone\n# does not prove the mitigation is active on the tested execution path.`,
    );
  }

  if (["vbs-hvci", "driver-signing-code-integrity"].includes(concept.slug)) {
    return makeDemo(
      "Capture virtualization and code-integrity state",
      "powershell",
      "Several independent signals distinguish hardware support, configured policy, services running, Secure Boot, and effective code-integrity enforcement.",
      `$deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard ` +
        `-Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue\n\n[ordered]@{\n  Mitigation = ${JSON.stringify(concept.title)}\n  Build = Get-ComputerInfo | Select-Object WindowsProductName, OsBuildNumber\n  DeviceGuard = $deviceGuard\n  SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue\n  SystemMitigations = Get-ProcessMitigation -System\n}\n\n# Preserve event logs or a controlled load decision as enforcement evidence;\n# a configured registry value by itself is insufficient.`,
    );
  }

  if (
    ["smep-smap", "kdp", "pool-hardening", "secure-pool"].includes(concept.slug)
  ) {
    return makeDemo(
      "Verify kernel mitigation state and behavior",
      "windbg",
      "Use matching symbols in a disposable kernel-debugging VM. Static support, configured state, and an enforced fault or allocation property should be recorded separately.",
      `vertarget\n!sysinfo machineid\n!sysinfo cpuinfo\nr cr4\n!pool <test-allocation>\n!pte <test-address>\n\n; Mitigation: ${concept.title}\n; Record build, CPU/hypervisor features, policy, relevant control bits or\n; protected metadata, a permitted control case, and a blocked negative case.\n; Do not generalize one protected target to all kernel data or allocations.`,
    );
  }

  if (["kaslr", "kaslr-bypasses"].includes(concept.slug)) {
    return makeDemo(
      "Measure address randomization across clean boots",
      "windbg",
      "One module base does not measure entropy or a bypass. Capture several clean boots and label whether each address came from a legitimate disclosure, debugger visibility, or an inference.",
      `vertarget\nlm m nt\nlm m <target-module>\n!address <target-address>\n\n; Mitigation: ${concept.title}\n; Repeat only after a true reboot and record:\n; build, boot identifier, module hash, module base, object/heap address if relevant,\n; disclosure source, required privilege, stability window, and negative control.`,
    );
  }

  return makeDemo(
    "Separate supported, configured, active, and effective",
    "powershell",
    "A mitigation conclusion needs runtime evidence from the exact target and build, not only product documentation or a registry setting.",
    `$snapshot = [ordered]@{\n  Concept = ${JSON.stringify(concept.title)}\n  Build = [System.Environment]::OSVersion.VersionString\n  ComputerInfo = Get-ComputerInfo | Select-Object WindowsProductName, OsBuildNumber\n  SystemMitigations = Get-ProcessMitigation -System\n  DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard ` +
      `-Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue\n}\n\n$snapshot | ConvertTo-Json -Depth 6\n\n# Add an allowed control case and a blocked case at the exact protected boundary.`,
  );
}

function buildWorkflowDemo(concept: HandbookConcept): ConceptDemo {
  if (concept.slug === "kernel-debugging") {
    return makeDemo(
      "Start a reproducible kernel-debugging session",
      "windbg",
      "The session begins by pinning build, symbol state, modules, process, and thread before any hypothesis-specific breakpoints are added.",
      `.symfix\n.sympath+ C:\\Symbols\n.reload /f\nvertarget\n!sysinfo machineid\nlm\n!process 0 0\n!thread\n\n; Workflow: ${concept.title}\n; Save debugger version, target build, module hashes, symbol diagnostics,\n; breakpoint commands, call stacks, and the negative-control run.`,
    );
  }

  if (concept.slug === "driver-fuzzing") {
    return makeDemo(
      "Keep the harness stateful and evidence-driven",
      "python",
      "This deliberately non-operational harness skeleton shows the metadata a safe lab needs before a generated case can be called meaningful.",
      `from dataclasses import dataclass\n\n@dataclass(frozen=True)\nclass TestCase:\n    endpoint: str\n    operation: int\n    protocol_state: str\n    payload: bytes\n    expected_reset: str\n\ndef execute_read_only(case: TestCase) -> dict:\n    # Implement only against an owned disposable target.\n    raise NotImplementedError("add snapshot reset, timeout, coverage, and crash capture")\n\nseed = TestCase(\n    endpoint="record reachable lab endpoint",\n    operation=0,\n    protocol_state="initialized",\n    payload=b"valid-seed-first",\n    expected_reset="clean snapshot",\n)\n\n# Workflow: ${concept.title}; retain coverage and rejected-state evidence.`,
    );
  }

  if (concept.slug === "static-analysis") {
    return makeDemo(
      "Turn static leads into a reachable call-path ledger",
      "python",
      "Imports and decompiler matches are leads. Store the entry point, caller, guards, taint transformations, sink, and dynamic confirmation needed for a finding.",
      `lead = {\n    "workflow": ${JSON.stringify(concept.title)},\n    "entry_point": "device, callback, parser, IPC method, or internal-only",\n    "least_privileged_reachability": "unknown",\n    "attacker_controlled_fields": [],\n    "guards": [],\n    "transformations": [],\n    "sensitive_sink": "record exact argument and authority",\n    "dynamic_confirmation": "pending",\n    "negative_control": "pending",\n}\n\nassert lead["entry_point"] != "", "An import list is not a call path"`,
    );
  }

  if (concept.slug === "patch-diffing") {
    return makeDemo(
      "Translate a patch into a semantic variant rule",
      "python",
      "The useful output of a diff is an invariant-restoration rule with true and false tests, not merely a list of changed basic blocks.",
      `patch = {\n    "workflow": ${JSON.stringify(concept.title)},\n    "vulnerable_hash": "record SHA-256",\n    "fixed_hash": "record SHA-256",\n    "changed_guard": "describe the added check or state transition",\n    "restored_invariant": "object.property must remain true before operation",\n    "variant_query": "search sibling entry points for the missing invariant",\n    "positive_test": "vulnerable shape reaches the unsafe transition",\n    "negative_test": "fixed shape rejects before the transition",\n}\n\nassert patch["changed_guard"] != patch["restored_invariant"]`,
    );
  }

  if (concept.slug === "runtime-tracing") {
    return makeDemo(
      "Capture a narrow, timestamped runtime trace",
      "powershell",
      "Use an owned VM and a minimal provider set. Correlate request, process/thread, stack, object, status, and cleanup instead of collecting an unbounded trace.",
      `$traceName = 'WindowsSecurityConceptLab'\n$tracePath = 'C:\\Lab\\trace.etl'\n\nlogman.exe query providers\nwpr.exe -profiles\n\n[ordered]@{\n  Workflow = ${JSON.stringify(concept.title)}\n  TraceName = $traceName\n  Output = $tracePath\n  Build = [System.Environment]::OSVersion.VersionString\n  StartUtc = (Get-Date).ToUniversalTime().ToString('o')\n} | ConvertTo-Json\n\n# Define start/stop commands for the selected profile in the lab notebook and\n# verify cleanup even when the reproducer times out or the target exits.`,
    );
  }

  if (
    ["byovd", "symbols-and-structures", "lab-design"].includes(concept.slug)
  ) {
    return makeDemo(
      "Create a version-pinned evidence manifest",
      "powershell",
      "A reproducible lab couples the claim to exact artifacts, symbols, mitigation state, isolation, and cleanup rather than a floating filename or screenshot.",
      `$artifact = 'C:\\Lab\\example.sys'\n\n[ordered]@{\n  Workflow = ${JSON.stringify(concept.title)}\n  Build = Get-ComputerInfo | Select-Object WindowsProductName, OsBuildNumber\n  Artifact = Get-Item -LiteralPath $artifact -ErrorAction SilentlyContinue |\n    Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc\n  Hash = Get-FileHash -Algorithm SHA256 -LiteralPath $artifact -ErrorAction SilentlyContinue\n  Signature = Get-AuthenticodeSignature -FilePath $artifact -ErrorAction SilentlyContinue\n  Mitigations = Get-ProcessMitigation -System\n  Identity = whoami.exe /all\n}\n\n# Add symbol identity/GUID-age, snapshot ID, commands, negative results, and cleanup.`,
    );
  }

  return makeDemo(
    "Store every claim with evidence and confidence",
    "python",
    "A structured record prevents a static lead, source assertion, or unpinned observation from silently becoming a confirmed result.",
    `from dataclasses import dataclass\n\n@dataclass(frozen=True)\nclass Evidence:\n    concept: str\n    build: str\n    artifact_sha256: str\n    observation: str\n    negative_control: str\n    confidence: str\n\nrecord = Evidence(\n    concept=${JSON.stringify(concept.title)},\n    build="record-exact-build",\n    artifact_sha256="record-real-hash",\n    observation="what was directly observed",\n    negative_control="what correctly failed",\n    confidence="hypothesis",  # lead | hypothesis | confirmed\n)\n\nassert record.confidence != "confirmed" or record.negative_control`,
  );
}

function buildDemo(concept: HandbookConcept): ConceptDemo {
  if (concept.demo) return concept.demo;

  if (concept.group === "primitives") return buildPrimitiveDemo(concept);
  if (concept.group === "vulnerability-classes")
    return buildVulnerabilityDemo(concept);
  if (concept.group === "attack-surfaces")
    return buildAttackSurfaceDemo(concept);
  if (concept.group === "driver-types") return buildDriverTypeDemo(concept);
  if (concept.group === "lpe-services") return buildLpeDemo(concept);
  if (concept.group === "mitigations") return buildMitigationDemo(concept);
  if (concept.group === "research-workflow") return buildWorkflowDemo(concept);

  const foundationDemo = buildFoundationDemo(concept);
  if (foundationDemo) return foundationDemo;

  return makeDemo(
    "Capture identity and object state before interpretation",
    "powershell",
    "These read-only commands create a reproducible identity and build snapshot before deeper tracing of the concept.",
    `$evidence = [ordered]@{\n  Concept = ${JSON.stringify(concept.title)}\n  Timestamp = (Get-Date).ToUniversalTime().ToString('o')\n  Build = [System.Environment]::OSVersion.VersionString\n  Identity = whoami.exe /all\n  Privileges = whoami.exe /priv\n}\n\n$evidence | ConvertTo-Json -Depth 4\n\n# Relevant interfaces: ${apiNames(concept)}`,
  );
}

export function buildConceptDeepDive(
  concept: HandbookConcept,
): ConceptDeepDive {
  const profile = groupProfiles[concept.group];
  const scenario = scenarioBySlug[concept.slug] ?? defaultScenario(concept);
  const primaryQuestion =
    concept.questions[0] ?? "Which trust boundary is crossed?";
  const controlQuestion =
    concept.questions[1] ?? "What does the caller control independently?";
  const buildQuestion =
    concept.questions[2] ?? "Which build and policy assumptions apply?";
  const negativeQuestion =
    concept.questions[3] ?? "Which negative control would falsify the claim?";

  return {
    context: [
      ...profile.context,
      `${concept.title} is specifically about this boundary: ${concept.summary} The useful mental model is: ${concept.mentalModel}`,
      `In practice, the concept is used to ${concept.enables.join(", ").toLocaleLowerCase()}. Those are separate claims. Each needs its own evidence, starting identity, target object, and failure condition rather than being inferred from the concept name.`,
    ],
    invariant: {
      expected: `${profile.invariant} For ${concept.title}, the expected behavior can be tested by asking: ${primaryQuestion}`,
      failure: `${profile.failure} The first concrete review question is: ${controlQuestion}`,
      securityEffect: `${concept.whyItMatters} A valid impact statement must still answer: ${buildQuestion}`,
    },
    example: {
      title: `Worked example: reason about ${concept.title}`,
      setup: scenario,
      steps: [
        `Start from the least-privileged principal and record the exact object, endpoint, handle, or state involved. Do not begin from the final privileged result.`,
        ...concept.mechanics,
        `Independently verify the resulting state, then run a negative control based on this question: ${negativeQuestion}`,
      ],
      observation: `The result is useful only if it demonstrates the specific capability rather than a nearby symptom. For this concept, the first three claims to test separately are: ${concept.enables.join("; ")}.`,
      lesson: `The example is not a universal exploit recipe. Its purpose is to keep the boundary, invariant, measured capability, conversion assumptions, mitigation state, and final evidence separate enough that another researcher can reproduce or reject each step.`,
    },
    constraints: [
      {
        dimension: "Reachability",
        question: primaryQuestion,
        evidence:
          "Endpoint security, granted handle rights, activation state, and a trace proving the intended handler or privileged consumer is reached.",
      },
      {
        dimension: "Caller control",
        question: controlQuestion,
        evidence:
          "One-variable tests showing which target, value, path, identity, size, state, or timing properties the caller controls independently.",
      },
      {
        dimension: "Lifetime and repetition",
        question:
          "Does the behavior survive asynchronous handoff, duplication, cancellation, cleanup, close, restart, and repeated invocation?",
        evidence:
          "Reference/lifetime traces, repeated runs from clean snapshots, and explicit failure behavior during teardown or concurrent activity.",
      },
      {
        dimension: "Build and mitigation state",
        question: buildQuestion,
        evidence:
          "Exact build, binary hashes, symbols, policy, firmware/CPU or virtualization state, and runtime proof that the relevant control is active.",
      },
      {
        dimension: "Impact proof",
        question: negativeQuestion,
        evidence:
          "An independent before/after observation of the final object, token, access right, bytes, code-loading decision, or protected action plus a negative control.",
      },
    ],
    evidence: list([
      ...profile.evidence,
      `Record the interfaces that appear in this concept (${apiNames(concept)}) with arguments, access masks, status values, and call context rather than as an unqualified API list.`,
      `Preserve the source trail (${concept.sources.map((source) => source.title).join(", ") || "primary platform documentation"}) and mark which statements are documented, directly observed, or inferred.`,
    ]),
    pitfalls: list([
      ...profile.pitfalls,
      `Mistaking "${concept.summary}" for a complete impact statement. It describes the concept; it does not prove reachability, controllability, or final authority on a particular build.`,
      `Combining the claims "${concept.enables.join('", "')}" into one result. A sound writeup tests and labels each capability separately.`,
    ]),
    defenses: list([
      ...profile.defenses,
      `Turn each audit question into a regression test. In particular: ${primaryQuestion}`,
      `Document and monitor the sensitive interfaces (${apiNames(concept)}) at the point where they authorize, resolve, or perform the privileged operation.`,
    ]),
    lab: {
      objective: `Produce a build-pinned, non-destructive evidence bundle that explains ${concept.title}, measures its relevant constraints, and includes at least one negative control.`,
      setup: profile.labSetup,
      procedure: [
        ...profile.labProcedure,
        `Answer every audit question on this page with observed, documented, inferred, or unknown; never leave the evidence class implicit.`,
      ],
      expected: [
        ...profile.labExpected,
        `A concise conclusion stating whether the observations are sufficient to ${concept.enables[0]?.toLocaleLowerCase() ?? "support the stated capability"}.`,
      ],
      cleanup: [
        "Stop tracing and verifier settings that were enabled only for the experiment.",
        "Restore changed permissions, policy, services, files, registry values, and boot configuration, or revert the disposable snapshot.",
        "Archive commands, hashes, traces, negative results, and environment metadata without retaining sensitive host data.",
      ],
      demo: buildDemo(concept),
    },
  };
}

export const authoredScenarioSlugs = new Set(Object.keys(scenarioBySlug));
