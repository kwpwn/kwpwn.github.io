import type {
  ConceptApi,
  ConceptSource,
  HandbookConcept,
  HandbookGroupId,
} from "./windows-security-handbook";

export interface ConceptSeed {
  slug: string;
  title: string;
  group: HandbookGroupId;
  summary: string;
  model: string;
  enables: string[];
  checks: string[];
  steps?: string[];
  sources?: ConceptSource[];
  source?: string;
  related?: string[];
  aliases?: string[];
  apis?: ConceptApi[];
  demo?: HandbookConcept["demo"];
  level?: HandbookConcept["level"];
  featured?: boolean;
}

const whyByGroup: Record<HandbookGroupId, string> = {
  foundations:
    "This contract is part of the base model used to interpret reachability, authorization, object identity, lifetime, and impact.",
  primitives:
    "The exact capability and its constraints determine which targets and compositions are realistic.",
  "vulnerability-classes":
    "A root-cause label is useful only when it names the broken invariant and guides variant analysis beyond one crashing input.",
  "attack-surfaces":
    "Mapping the entry point, caller identity, protocol state, and privileged operation exposes both reachable bugs and missing authorization boundaries.",
  "driver-types":
    "Driver family predicts reachable interfaces, lifecycle complexity, attacker-controlled state, and the privileged resources a flaw may expose.",
  "lpe-services":
    "A reliable LPE explanation must connect the weaker principal to the exact stronger principal and sensitive action that complete the chain.",
  mitigations:
    "Mitigations remove assumptions rather than making every bug harmless. Exploit strategy must be recalculated for the exact build and policy state.",
  "research-workflow":
    "A repeatable method turns observations into evidence, reduces false claims, and makes a result reproducible on a pinned target.",
};

const defaultSteps: Record<HandbookGroupId, string[]> = {
  foundations: [
    "Identify the involved Windows objects and the identity attached to each operation.",
    "Trace the documented contract across creation, use, and teardown.",
    "Locate the access check, validation, or lifetime transition that enforces the contract.",
    "Confirm behavior on the exact Windows build with symbols and observable evidence.",
  ],
  primitives: [
    "Locate the operation that first grants attacker influence.",
    "Measure independent control over target, value, size, timing, identity, and repetition.",
    "Select a compatible consumer or target that upgrades the capability.",
    "Verify final authority, mitigation state, stability, and cleanup.",
  ],
  "vulnerability-classes": [
    "Write the intended invariant in one sentence before naming the bug class.",
    "Find the first operation that violates that invariant, not only the later crash.",
    "Determine which data, object, identity, or lifetime becomes attacker-controlled.",
    "Search sibling handlers and structurally similar paths for the same missing invariant.",
  ],
  "attack-surfaces": [
    "Enumerate endpoints, operations, dispatch tables, callbacks, and registration state.",
    "Record who can reach each entry point and under which token, session, mode, or device state.",
    "Trace input parsing, object lookup, authorization, lifetime, and privileged side effects.",
    "Exercise the smallest safe request in an isolated, version-pinned lab and collect traces.",
  ],
  "driver-types": [
    "Identify the device stack, framework, load trigger, and owning service or hardware.",
    "Map user-mode, kernel-mode, hardware, callback, and management-plane entry points.",
    "Prioritize operations that cross identity, memory, filesystem, network, or device-isolation boundaries.",
    "Validate assumptions against the exact driver version, INF policy, and Windows build.",
  ],
  "lpe-services": [
    "Start as the least-privileged principal in scope and record all existing rights.",
    "Identify the controlled object, configuration, path, endpoint, or token transition.",
    "Name the privileged consumer and the exact action it performs with stronger authority.",
    "Prove the final token or protected-object access and document detection and cleanup artifacts.",
  ],
  mitigations: [
    "Confirm whether the control is supported, configured, and active on the target—not merely present in documentation.",
    "Name the exploit assumption the control invalidates.",
    "Re-evaluate target selection, data-only options, valid call targets, mappings, and information requirements.",
    "Record remaining attack paths and the evidence that the chosen composition still works.",
  ],
  "research-workflow": [
    "State one falsifiable question and the evidence needed to answer it.",
    "Pin binaries, symbols, configuration, mitigations, and target build.",
    "Automate the smallest repeatable observation or experiment.",
    "Preserve commands, traces, hashes, crashes, and negative results for later review.",
  ],
};

export function makeConcept(seed: ConceptSeed): HandbookConcept {
  const fallbackSource: ConceptSource[] = seed.source
    ? [
        {
          title: `${seed.title} reference`,
          href: seed.source,
          kind: "reference",
        },
      ]
    : [];

  return {
    slug: seed.slug,
    title: seed.title,
    group: seed.group,
    level: seed.level ?? "Intermediate",
    summary: seed.summary,
    mentalModel: seed.model,
    whyItMatters: whyByGroup[seed.group],
    enables: seed.enables,
    mechanics: seed.steps ?? defaultSteps[seed.group],
    questions: seed.checks,
    apis: seed.apis,
    demo: seed.demo,
    sources: seed.sources ?? fallbackSource,
    related: seed.related ?? [],
    aliases: seed.aliases,
    featured: seed.featured,
  };
}
