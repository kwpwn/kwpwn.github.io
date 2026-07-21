import type { HandbookConcept } from "./windows-security-handbook";
import { makeConcept } from "./windows-security-catalog-helpers";

const ks = "https://splintersfury.github.io/KernelSight";

export const workflowConcepts: HandbookConcept[] = [
  makeConcept({
    slug: "why-kernel-drivers",
    title: "Why kernel drivers matter",
    group: "research-workflow",
    level: "Foundation",
    summary:
      "Drivers extend the trusted kernel with hardware, filesystem, network, security, and vendor functionality, so their reachability and authority can turn small validation mistakes into system-wide impact.",
    model:
      "Driver risk is exposure × authority × complexity × deployment. A widely installed, user-reachable utility driver with physical-memory operations deserves different priority from an internal kernel-only filter.",
    enables: [
      "Prioritize targets",
      "Connect driver type to likely impact",
      "Explain why signing is not sufficient",
    ],
    checks: [
      "How widely is the driver deployed?",
      "Which least-privileged caller can reach it?",
      "Which kernel, device, or hardware authority does it expose?",
      "Who owns update and revocation?",
    ],
    source: `${ks}/guides/why-kernel-drivers/`,
    related: [
      "trust-boundaries",
      "vendor-utility-drivers",
      "driver-signing-code-integrity",
    ],
  }),
  makeConcept({
    slug: "secure-driver-anatomy",
    title: "Anatomy of a secure driver interface",
    group: "research-workflow",
    summary:
      "A secure interface combines restrictive installation and device security, least-privilege IOCTL rights, simple protocols, per-handle authorization, framework-safe buffers, state validation, and robust lifecycle handling.",
    model:
      "Defense is layered: admission, open, operation, buffer, object identity, lifetime, and telemetry. No single magic value, signature, DACL, or bounds check replaces the other layers.",
    enables: [
      "Review driver design systematically",
      "Write actionable remediation",
      "Distinguish platform controls from vendor protocol",
    ],
    checks: [
      "Is the device DACL least privilege?",
      "Do IOCTL access bits match operation sensitivity?",
      "Is authorization bound to the file object?",
      "Are every state transition, buffer, and teardown path validated?",
    ],
    source: `${ks}/guides/secure-driver-anatomy/`,
    related: [
      "driver-gates-and-handshakes",
      "ioctl-encoding-and-buffering",
      "wdf-kmdf",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "exploit-chain-patterns",
    title: "Exploit-chain patterns",
    group: "research-workflow",
    summary:
      "A chain composes exposure, root cause, primitive, resolver, target, mitigation response, trigger, verification, and cleanup into final authority.",
    model:
      "Use a typed pipeline rather than prose leaps: entry point → invariant break → measured capability → missing information → upgrade → final protected action.",
    enables: [
      "Expose missing exploit steps",
      "Compare different bugs by capability",
      "Choose case studies that teach reusable conversions",
    ],
    checks: [
      "Which step is demonstrated versus assumed?",
      "What environmental preconditions exist?",
      "Which mitigation changes the chosen target?",
      "How is final authority verified and state restored?",
    ],
    source: `${ks}/guides/exploit-chain-patterns/`,
    related: [
      "trust-boundaries",
      "arbitrary-read-write-primitives",
      "mitigation-timeline",
    ],
    featured: true,
  }),
  makeConcept({
    slug: "mitigation-timeline",
    title: "Mitigation timeline and build awareness",
    group: "research-workflow",
    summary:
      "Windows security behavior changes by build, servicing state, hardware capability, SKU, policy, and feature enablement, so historical exploit techniques need a dated target matrix.",
    model:
      "Pin OS build, image hashes, symbols, security feature state, driver version, firmware/CPU features, and update level before interpreting a result.",
    enables: [
      "Avoid applying obsolete offsets or primitives",
      "Explain when a technique stopped working",
      "Select historically accurate labs",
    ],
    checks: [
      "What exact build and revision are tested?",
      "Is the mitigation active or only supported?",
      "Did structure layout, policy, or allocator behavior change?",
      "Can results be reproduced from archived binaries and symbols?",
    ],
    source: `${ks}/guides/mitigation-timeline/`,
    related: ["patch-diffing", "vbs-hvci", "symbols-and-structures"],
  }),
  makeConcept({
    slug: "patch-patterns",
    title: "Patch patterns and variant analysis",
    group: "research-workflow",
    summary:
      "Security fixes commonly add size validation, reference ownership, authorization, object-identity checks, state guards, synchronization, initialization, or safer APIs—patterns that guide sibling-code review.",
    model:
      "Translate a binary diff into an invariant: what new condition must be true, what resource is now owned, or what state transition is forbidden? Then search semantically similar paths.",
    enables: [
      "Find variants",
      "Explain the root cause from a patch",
      "Detect partial or inconsistent fixes",
    ],
    checks: [
      "Which new branch or data dependency changes security?",
      "Is the check before every use?",
      "Do sibling handlers share the old helper?",
      "Can integer, race, or alternate-protocol paths bypass the repair?",
    ],
    source: `${ks}/guides/patch-patterns/`,
    related: ["patch-diffing", "static-analysis", "vulnerability-classes"],
  }),
  makeConcept({
    slug: "corpus-analytics",
    title: "Vulnerability corpus analytics",
    group: "research-workflow",
    summary:
      "A normalized corpus turns CVEs, drivers, primitives, root causes, attack surfaces, mitigations, versions, and sources into comparable evidence rather than an unstructured bookmark list.",
    model:
      "Separate observed facts from inferred tags. Preserve source provenance, affected/fixed versions, confidence, duplicates, missing data, and the difference between root cause and exploit primitive.",
    enables: [
      "Prioritize recurring bug families",
      "Measure coverage gaps",
      "Connect case studies to concepts and tools",
    ],
    checks: [
      "Does every tag have source evidence?",
      "Are CVE records deduplicated across aliases?",
      "Are unknown values preserved rather than guessed?",
      "Can the corpus be regenerated and schema-validated?",
    ],
    source: `${ks}/guides/corpus-analytics/`,
    related: ["research-evidence", "patch-patterns", "case-study-library"],
  }),
  makeConcept({
    slug: "kernel-debugging",
    title: "Kernel debugging",
    group: "research-workflow",
    summary:
      "Kernel debugging proves reachability, caller context, object state, allocator behavior, corruption geometry, mitigation status, crashes, and control flow on a pinned target.",
    model:
      "Use symbols and hypotheses. Break on the smallest meaningful transition, inspect typed state, automate repetitive commands, and record both expected and negative observations.",
    enables: [
      "Confirm root cause and controllability",
      "Measure objects and pool state",
      "Capture reproducible crash and exploit evidence",
    ],
    checks: [
      "Are symbols correct for every loaded image?",
      "Which breakpoint answers the current question?",
      "Does debugging alter race timing or verifier behavior?",
      "Can the observation be scripted and repeated after reboot?",
    ],
    source: `${ks}/tooling/debugging/`,
    related: ["symbols-and-structures", "runtime-tracing", "lab-design"],
    featured: true,
  }),
  makeConcept({
    slug: "driver-fuzzing",
    title: "Driver fuzzing",
    group: "research-workflow",
    summary:
      "Driver fuzzing mutates IOCTLs, protocols, files, packets, state sequences, and lifecycle events while collecting coverage, crashes, hangs, and verifier signals in recoverable snapshots.",
    model:
      "A useful harness reaches meaningful code in valid state. Model initialization, handles, dependent calls, checksums, object lifetime, reset, nondeterminism, and coverage—not only random bytes.",
    enables: [
      "Discover memory-safety and logic bugs",
      "Explore stateful interfaces",
      "Generate minimized, replayable inputs",
    ],
    checks: [
      "What code coverage proves the harness is deep?",
      "Which request sequence establishes required state?",
      "Can every iteration reset deterministically?",
      "Are crashes deduplicated by root cause rather than stack address alone?",
    ],
    source: `${ks}/tooling/fuzzing/`,
    related: ["ioctl-handlers", "unsafe-protocol-parsing", "lab-design"],
  }),
  makeConcept({
    slug: "static-analysis",
    title: "Static analysis",
    group: "research-workflow",
    summary:
      "Static analysis scales searches for dangerous API use, unchecked arithmetic, user-pointer flows, missing authorization, lifetime imbalances, and variants across source or recovered code.",
    model:
      "Start with one semantic question, define trustworthy sources and sensitive sinks, model sanitizers and ownership, inspect every result, and preserve a test corpus for the query.",
    enables: [
      "Find variants beyond one handler",
      "Audit source-level data flow",
      "Encode review knowledge as repeatable checks",
    ],
    checks: [
      "What exact pattern or flow is security-relevant?",
      "Which framework helpers validate buffers or rights?",
      "How are false positives and unknown calls modeled?",
      "Does a real vulnerable and fixed sample test the rule?",
    ],
    source: `${ks}/tooling/static-analysis/`,
    related: ["patch-patterns", "driver-fuzzing", "research-evidence"],
  }),
  makeConcept({
    slug: "patch-diffing",
    title: "Patch diffing",
    group: "research-workflow",
    summary:
      "Patch diffing compares vulnerable and fixed binaries or source to identify changed functions, conditions, structures, data flow, and security invariants.",
    model:
      "Matching is a locator, not the conclusion. Recover the semantic change, validate reachability and affected versions, then test whether alternate paths preserve the old invariant violation.",
    enables: [
      "Recover root cause from updates",
      "Prioritize changed attack-surface code",
      "Find incomplete fixes and variants",
    ],
    checks: [
      "Are binaries from comparable builds and symbols?",
      "Which compiler noise can be ignored?",
      "What security decision changed?",
      "Can the fix be bypassed through a sibling path or alternate representation?",
    ],
    source: `${ks}/tooling/patch-diffing/`,
    related: ["patch-patterns", "mitigation-timeline", "static-analysis"],
    featured: true,
  }),
  makeConcept({
    slug: "byovd",
    title: "Bring Your Own Vulnerable Driver",
    group: "research-workflow",
    summary:
      "BYOVD uses a legitimately signed but vulnerable or overly powerful driver to obtain kernel or hardware capabilities after the attacker already has enough authority to load or access it.",
    model:
      "Separate load prerequisites, signing/block policy, device exposure, gate emulation, backend primitive, target build, and final objective. Existing admin-to-kernel capability is different from standard-user LPE.",
    enables: [
      "Study signed-driver abuse",
      "Map blocklist and WDAC policy",
      "Compose vendor utility interfaces into defensive research",
    ],
    checks: [
      "Who can install and start the driver?",
      "Is it blocked on the exact system?",
      "Can the existing device be opened without loading a new driver?",
      "Which operation and target turn it into real impact?",
    ],
    source: `${ks}/reference/byovd/`,
    related: [
      "vendor-utility-drivers",
      "driver-signing-code-integrity",
      "direct-ioctl-read-write",
    ],
  }),
  makeConcept({
    slug: "symbols-and-structures",
    title: "Symbols, structures, and build-aware types",
    group: "research-workflow",
    summary:
      "Windows internal layouts and Native API declarations vary across builds, so offsets and types should come from matching symbols, versioned references, or auditable definitions.",
    model:
      "Treat every offset as a versioned fact with provenance. Prefer symbols and type information; use phnt/NtDoc for declarations and Vergilius for comparison, then confirm on the target.",
    enables: [
      "Avoid stale hard-coded offsets",
      "Interpret kernel objects accurately",
      "Build reproducible debugger and parser tooling",
    ],
    checks: [
      "Do PDB GUID/age and image hash match?",
      "Is the type public, private, inferred, or reverse engineered?",
      "Which build introduced or moved the field?",
      "Can the code derive the offset rather than embed it?",
    ],
    sources: [
      {
        title: "phnt",
        href: "https://github.com/winsiderss/phnt",
        kind: "reference",
      },
      { title: "NtDoc", href: "https://ntdoc.m417z.com/", kind: "reference" },
      {
        title: "Vergilius Project",
        href: "https://www.vergiliusproject.com/",
        kind: "reference",
      },
    ],
    related: [
      "kernel-debugging",
      "mitigation-timeline",
      "windows-memory-manager",
    ],
  }),
  makeConcept({
    slug: "runtime-tracing",
    title: "Runtime tracing and telemetry",
    group: "research-workflow",
    summary:
      "ETW, Procmon, WPR/WPA, debugger events, callbacks, and purpose-built instrumentation correlate static code with files, registry, images, handles, RPC, I/O, scheduling, and timing at runtime.",
    model:
      "Select the least invasive signal that answers the hypothesis, preserve timestamps and stacks, and account for dropped events, provider enablement, buffering, and the observer changing timing.",
    enables: [
      "Map hidden control flow",
      "Identify privileged consumers and triggers",
      "Measure race windows and object lifetime",
    ],
    checks: [
      "Which event proves the transition?",
      "Are stacks and symbols available?",
      "Can events be lost or filtered?",
      "Does instrumentation change the bug's timing or behavior?",
    ],
    related: ["wmi-etw", "kernel-debugging", "research-evidence"],
  }),
  makeConcept({
    slug: "lab-design",
    title: "Reproducible Windows research labs",
    group: "research-workflow",
    summary:
      "A safe lab pins OS build, patches, binaries, symbols, drivers, firmware/CPU features, mitigations, snapshots, network exposure, debugging transport, and reset procedures.",
    model:
      "The lab is part of the evidence. Record what differs from production, keep risky drivers and samples isolated, and make every destructive change disposable and recoverable.",
    enables: [
      "Repeat crashes and race conditions",
      "Compare mitigation states",
      "Share exact reproduction prerequisites",
    ],
    checks: [
      "Can the VM be restored automatically?",
      "Is the host protected from risky drivers and network services?",
      "Are test-signing, Secure Boot, HVCI, and verifier state documented?",
      "Are symbols and artifacts archived with hashes?",
    ],
    related: ["kernel-debugging", "driver-fuzzing", "research-evidence"],
  }),
  makeConcept({
    slug: "research-evidence",
    title: "Evidence and claim quality",
    group: "research-workflow",
    level: "Foundation",
    summary:
      "High-quality security notes separate observed behavior, source-backed facts, debugger evidence, inference, environmental assumptions, and untested hypotheses.",
    model:
      "For each claim, store source, target build, command or breakpoint, expected observation, actual observation, confidence, and what would falsify it.",
    enables: [
      "Produce trustworthy writeups",
      "Avoid overstating crash impact",
      "Make negative results useful",
    ],
    checks: [
      "Is this fact observed, documented, or inferred?",
      "Can another researcher reproduce it?",
      "Is the least-privileged starting context stated?",
      "Are fixed versions, mitigations, detection, and cleanup included?",
    ],
    related: ["corpus-analytics", "lab-design", "exploit-chain-patterns"],
  }),
  makeConcept({
    slug: "autopiff-integration",
    title: "Automated driver patch-diff pipelines",
    group: "research-workflow",
    level: "Advanced",
    summary:
      "An AutoPiff-style pipeline turns recurring Windows driver updates into version-paired, decompiled, reachability-filtered, semantically classified, and reviewable patch evidence.",
    model:
      "Treat automation as a narrowing funnel: acquire comparable binaries, match functions, remove compiler noise, recover the changed invariant, prove that changed code is reachable from a caller-controlled surface, then rank the result for manual validation.",
    enables: [
      "Triage Patch Tuesday driver changes at scale",
      "Map binary changes to vulnerability classes and attack surfaces",
      "Preserve reproducible evidence for later variant analysis",
    ],
    steps: [
      "Acquire the previous and current driver builds with version metadata, hashes, signatures, symbols, and servicing provenance.",
      "Match functions structurally and isolate meaningful control-flow, data-flow, call, constant, and structure changes.",
      "Decompile candidate functions and trace backward to user-reachable IOCTL, IRP, callback, file, packet, or management entry points.",
      "Classify the new invariant (bounds, authorization, lifetime, initialization, synchronization, object identity, or requestor-mode handling) and score confidence separately from severity.",
      "Validate the hypothesis manually on pinned builds, retain negative results, and search sibling handlers for the unfixed pattern.",
    ],
    checks: [
      "Are both binaries directly comparable, or did the toolchain/configuration change?",
      "Does the changed function have a real path from a less-trusted input?",
      "Is the detected pattern a security decision or only refactoring noise?",
      "Can every report be regenerated from archived artifacts and tool versions?",
    ],
    demo: {
      title: "Keep confidence separate from severity",
      language: "python",
      description:
        "A small triage model prevents an interesting patch pattern from becoming a high-confidence vulnerability claim until reachability and manual validation are present.",
      code: `from dataclasses import dataclass

@dataclass(frozen=True)
class DiffFinding:
    semantic_pattern: str
    entrypoint_path: tuple[str, ...]
    manually_reproduced: bool
    severity: int

def confidence(finding: DiffFinding) -> str:
    if finding.manually_reproduced:
        return "confirmed"
    if finding.entrypoint_path:
        return "reachable-hypothesis"
    return "static-lead"

# Ranking may use severity, but the report must retain confidence.
finding = DiffFinding("added_bounds_check", ("IRP_MJ_DEVICE_CONTROL", "Parse"), False, 8)
print(confidence(finding))  # reachable-hypothesis`,
    },
    sources: [
      {
        title: "KernelSight AutoPiff integration",
        href: `${ks}/tooling/autopiff-integration/`,
        kind: "reference",
      },
      {
        title: "Karton distributed processing framework",
        href: "https://github.com/CERT-Polska/karton",
        kind: "reference",
      },
    ],
    related: [
      "patch-diffing",
      "patch-patterns",
      "static-analysis",
      "corpus-analytics",
    ],
  }),
  makeConcept({
    slug: "kdu-provider-compatibility",
    title: "KDU provider compatibility analysis",
    group: "research-workflow",
    level: "Advanced",
    summary:
      "KDU provider analysis asks whether a signed driver exposes the exact, reachable kernel or physical-memory capabilities required by a provider action, not merely whether the binary imports a dangerous routine.",
    model:
      "Compatibility is a capability-matching problem. Define the action, expand it into required primitives, prove each primitive is reachable through an accessible device protocol, then account for load rights, gates, target-build assumptions, and platform policy.",
    enables: [
      "Separate likely providers from confirmed reachable providers",
      "Map driver operations to MapDriver, DKOM, or other provider requirements",
      "Prioritize defensive review and block-policy decisions",
    ],
    steps: [
      "State the provider action and the minimum physical-memory, virtual-memory, translation, allocation, or object-manipulation capabilities it needs.",
      "Enumerate device names, security descriptors, IOCTLs, buffering modes, gates, and per-handle protocol state.",
      "Trace each IOCTL handler to the backend operation; an imported API alone is not evidence that a caller controls its arguments.",
      "Measure address, value, size, repetition, alignment, and target-build constraints for every candidate primitive.",
      "Record driver signing, revocation/blocklist state, HVCI/WDAC policy, load prerequisites, and whether the result starts from administrator or standard-user context.",
    ],
    checks: [
      "Which provider operation is being evaluated?",
      "Are all required primitives confirmed reachable from the same usable interface?",
      "Does the driver gate prove authorization, compatibility, or only packet shape?",
      "Are deployment and load prerequisites being confused with local privilege escalation?",
    ],
    demo: {
      title: "Match actions to confirmed capabilities",
      language: "python",
      description:
        "This defensive triage example only marks an action compatible when every required capability is confirmed reachable; imports and guesses stay outside the confirmed set.",
      code: `requirements = {
    "map_driver": {"read_phys", "write_phys", "virt_to_phys"},
    "dkom": {"write_kernel_virtual"},
}

confirmed_reachable = {"read_phys", "write_phys"}

for action, needed in requirements.items():
    missing = needed - confirmed_reachable
    status = "compatible" if not missing else f"missing: {sorted(missing)}"
    print(f"{action}: {status}")`,
    },
    sources: [
      {
        title: "KernelSight KDU provider compatibility analysis",
        href: `${ks}/reference/kdu-compatibility/`,
        kind: "reference",
      },
      {
        title: "KDU",
        href: "https://github.com/hfiref0x/KDU",
        kind: "reference",
      },
      {
        title: "LOLDrivers",
        href: "https://www.loldrivers.io/",
        kind: "reference",
      },
    ],
    related: [
      "byovd",
      "direct-ioctl-read-write",
      "dma-mmio-access",
      "driver-gates-and-handshakes",
    ],
  }),
  makeConcept({
    slug: "loldrivers-deep-analysis",
    title: "LOLDrivers deep analysis",
    group: "research-workflow",
    level: "Advanced",
    summary:
      "Deep corpus analysis enriches known vulnerable-driver hashes with architecture, mitigations, devices, IOCTLs, buffer methods, reachable privileged operations, protocol gates, and evidence-backed capability labels.",
    model:
      "Use two evidence tiers: fast static metadata for broad screening, then control-flow and data-flow validation from real entry points for confirmation. Keep imported capability, reachable capability, and exploitable capability as distinct fields.",
    enables: [
      "Prioritize risky signed drivers",
      "Compare driver families and recurring protocol designs",
      "Generate fuzzing, reversing, and block-policy queues",
    ],
    steps: [
      "Normalize hashes, aliases, signer chains, versions, architecture, device names, service metadata, and provenance without collapsing distinct builds.",
      "Extract PE mitigations, imports, dispatch registrations, IOCTL constants, buffering modes, access bits, embedded SDDL, and obvious gate material.",
      "Trace dangerous operations from reachable dispatch handlers and label caller control over each argument.",
      "Score exposure, capability, confidence, deployment, and mitigation posture independently so a single opaque risk number does not hide uncertainty.",
      "Version the dataset, preserve unknown values, and link every derived claim back to artifacts and analysis output.",
    ],
    checks: [
      "Does a dangerous import have a caller-reachable path?",
      "Can the caller actually control the sensitive arguments?",
      "Are duplicate hashes, family aliases, malicious samples, and vulnerable legitimate drivers distinguished?",
      "Can analysts reproduce every high-confidence capability label?",
    ],
    demo: {
      title: "Use evidence-tiered capability labels",
      language: "python",
      description:
        "A corpus should not promote an imported routine directly to an exposed primitive. The label records whether entry-point reachability and caller control have both been demonstrated.",
      code: `def capability_label(*, imported: bool, reachable: bool, caller_controls_args: bool) -> str:
    if reachable and caller_controls_args:
        return "confirmed-capability"
    if imported:
        return "static-lead"
    return "not-observed"

label = capability_label(
    imported=True,
    reachable=True,
    caller_controls_args=False,
)
print(label)  # static-lead`,
    },
    sources: [
      {
        title: "KernelSight LOLDrivers deep analysis",
        href: `${ks}/reference/loldrivers-analysis/`,
        kind: "reference",
      },
      {
        title: "DriverAtlas",
        href: "https://github.com/splintersfury/DriverAtlas",
        kind: "reference",
      },
      {
        title: "LOLDrivers",
        href: "https://www.loldrivers.io/",
        kind: "reference",
      },
    ],
    related: [
      "corpus-analytics",
      "byovd",
      "static-analysis",
      "kdu-provider-compatibility",
    ],
  }),
];
