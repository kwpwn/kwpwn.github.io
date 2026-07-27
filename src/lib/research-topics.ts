import type { CollectionEntry } from "astro:content";

export const RESEARCH_TOPIC_IDS = [
  "windows-privesc",
  "malware-c2",
  "windows-internals",
] as const;

export type ResearchTopicId = (typeof RESEARCH_TOPIC_IDS)[number];
export type ResearchTrackId =
  | "foundations"
  | "discovery-evidence"
  | "service-boundaries"
  | "execution-persistence"
  | "token-ipc"
  | "credentials-recovery"
  | "policy-controls"
  | "lateral-boundaries"
  | "static-analysis"
  | "dynamic-analysis"
  | "memory-execution"
  | "c2-operations"
  | "detection-engineering"
  | "boot-architecture"
  | "processes-execution"
  | "memory-manager"
  | "security-objects"
  | "io-drivers"
  | "ipc-services"
  | "telemetry-runtime"
  | "kernel-platform";

export interface ResearchTrack {
  id: ResearchTrackId;
  label: string;
  description: string;
}

export interface ResearchTopicPlacement {
  topic: ResearchTopicId;
  track: ResearchTrackId;
  order: number;
}

export interface ResearchTopic {
  id: ResearchTopicId;
  order: number;
  eyebrow: string;
  title: string;
  shortTitle: string;
  description: string;
  question: string;
  outcome: string;
  icon: string;
  recommendedStart: string;
  yunolayUrl: string;
  sourceBaselineCount: number;
  expectedLessonCount: number;
  tracks: ResearchTrack[];
}

export const RESEARCH_TOPICS: ResearchTopic[] = [
  {
    id: "windows-privesc",
    order: 1,
    eyebrow: "Privilege boundaries",
    title: "Windows Privilege Escalation",
    shortTitle: "Windows PrivEsc",
    description:
      "Build complete escalation chains from evidence: identify the actor, prove control over a privileged input, follow the consumer and sink, and validate the resulting security context.",
    question:
      "Which low-privileged control can influence code, data, identity, credentials, or policy consumed by a more privileged Windows component?",
    outcome:
      "You will be able to distinguish an interesting permission from a version-aware, reproducible escalation path and explain how to remediate the actual boundary failure.",
    icon: "lucide:shield-alert",
    recommendedStart: "windows-privesc-trust-boundary-model",
    yunolayUrl: "https://yunolay.com/category/windows-privesc/",
    sourceBaselineCount: 41,
    expectedLessonCount: 27,
    tracks: [
      {
        id: "foundations",
        label: "Security foundations",
        description:
          "Actors, tokens, SIDs, integrity levels, privileges, access checks, and the escalation proof model.",
      },
      {
        id: "discovery-evidence",
        label: "Discovery and evidence",
        description:
          "Repeatable enumeration, evidence grading, Windows event records, negative controls, and version-aware conclusions.",
      },
      {
        id: "service-boundaries",
        label: "Services and installers",
        description:
          "Service object DACLs, binary paths, installer policy, Print Spooler boundaries, and reliable trigger conditions.",
      },
      {
        id: "execution-persistence",
        label: "Execution and persistence",
        description:
          "DLL and COM activation, autoruns, scheduled tasks, WMI, LOLBins, and the privileged consumers behind them.",
      },
      {
        id: "token-ipc",
        label: "Tokens and IPC",
        description:
          "Impersonation levels, named pipes, Potato-family preconditions, UAC split tokens, and context transitions.",
      },
      {
        id: "credentials-recovery",
        label: "Credentials and recovery",
        description:
          "Backup and restore privileges, DPAPI, LSASS protections, Credential Guard, VSS, and secret-access boundaries.",
      },
      {
        id: "policy-controls",
        label: "Policy and controls",
        description:
          "AMSI, PowerShell language modes, AppLocker, WDAC, Windows Firewall, WFP, and policy verification.",
      },
      {
        id: "lateral-boundaries",
        label: "Adjacent trust boundaries",
        description:
          "Authentication coercion, relay preconditions, WSL integration, remote management, and cross-component reachability.",
      },
    ],
  },
  {
    id: "malware-c2",
    order: 2,
    eyebrow: "Behavior and communication",
    title: "Malware Analysis & C2",
    shortTitle: "Malware & C2",
    description:
      "Study malicious software as an observable system: file structure, execution state, persistence, tasking, transport, and the independent telemetry each transition leaves behind.",
    question:
      "What state changed, which component caused it, how did data move, and which independent sensor can confirm or reject the explanation?",
    outcome:
      "You will be able to analyze samples and C2 architecture without relying on signatures, unsafe detonation, or opaque tool output.",
    icon: "lucide:radio-tower",
    recommendedStart: "malware-c2-execution-tasking-telemetry-model",
    yunolayUrl: "https://yunolay.com/category/malware-c2/",
    sourceBaselineCount: 20,
    expectedLessonCount: 20,
    tracks: [
      {
        id: "foundations",
        label: "Analysis foundations",
        description:
          "Behavior models, evidence handling, isolated labs, acquisition records, and reproducible timelines.",
      },
      {
        id: "static-analysis",
        label: "Static analysis",
        description:
          "PE and Office containers, imports, strings, macros, structural anomalies, capability inference, and YARA quality.",
      },
      {
        id: "dynamic-analysis",
        label: "Dynamic analysis",
        description:
          "Controlled execution, process and registry timelines, unpacking, anti-analysis observations, and memory capture.",
      },
      {
        id: "memory-execution",
        label: "Memory and execution",
        description:
          "Shellcode, loaders, process injection, COFF and Beacon Object Files, memory permissions, and state transitions.",
      },
      {
        id: "execution-persistence",
        label: "Persistence and native tooling",
        description:
          "BITS, COM, run keys, services, WMI, Linux persistence, and living-off-the-land behavior as observable chains.",
      },
      {
        id: "c2-operations",
        label: "C2 architecture",
        description:
          "Tasking models, framework tradeoffs, HTTP, DNS and WebSocket semantics, redirectors, profiles, timing, and identity.",
      },
      {
        id: "detection-engineering",
        label: "Detection engineering",
        description:
          "AMSI, YARA, ETW, Sysmon, network metadata, behavioral joins, false-positive control, and regression tests.",
      },
    ],
  },
  {
    id: "windows-internals",
    order: 3,
    eyebrow: "Operating-system mechanics",
    title: "Windows Internals",
    shortTitle: "Windows Internals",
    description:
      "Connect documented Win32 behavior to executive objects, memory management, trust decisions, system calls, drivers, IPC, telemetry, and build-specific implementation evidence.",
    question:
      "Which object owns the state, which reference keeps it alive, which boundary validates the request, and where does the result return?",
    outcome:
      "You will be able to explain Windows behavior as a version-aware chain of objects and transitions rather than a list of isolated structures and offsets.",
    icon: "lucide:cpu",
    recommendedStart: "windows-process-thread-token-handle-model",
    yunolayUrl: "https://yunolay.com/category/windows-internals/",
    sourceBaselineCount: 31,
    expectedLessonCount: 32,
    tracks: [
      {
        id: "processes-execution",
        label: "Processes and execution",
        description:
          "EPROCESS, ETHREAD, KTHREAD, PEB, TEB, scheduling, thread pools, jobs, silos, and synchronization.",
      },
      {
        id: "boot-architecture",
        label: "Boot and architecture",
        description:
          "UEFI, Secure Boot, winload, kernel initialization, session creation, and the layered Windows architecture.",
      },
      {
        id: "memory-manager",
        label: "Memory manager",
        description:
          "Page tables, PTEs, VADs, working sets, heaps, sections, cache management, kernel pool, and copy-on-write.",
      },
      {
        id: "security-objects",
        label: "Objects and security",
        description:
          "Object namespaces, handles, tokens, SIDs, DACLs, LSA, logon sessions, references, and lifetime.",
      },
      {
        id: "io-drivers",
        label: "I/O and drivers",
        description:
          "IRPs, device stacks, IOCTLs, WDM, KMDF, Filter Manager, minifilters, buffering, completion, and cancellation.",
      },
      {
        id: "ipc-services",
        label: "IPC and services",
        description:
          "SCM, svchost, ALPC, WMI, registry providers, service identity, namespaces, and impersonation boundaries.",
      },
      {
        id: "telemetry-runtime",
        label: "Runtime and telemetry",
        description:
          "System calls, WOW64, ETW, SEH, VEH, unwind metadata, KUSER_SHARED_DATA, tracing, and debugger evidence.",
      },
      {
        id: "kernel-platform",
        label: "Kernel platform",
        description:
          "IRQL, interrupts, DPCs, APCs, PatchGuard, DSE, HVCI, win32k, the loader, and mitigation state.",
      },
    ],
  },
];

export function isResearchTopicId(value: string): value is ResearchTopicId {
  return RESEARCH_TOPIC_IDS.includes(value as ResearchTopicId);
}

export function getResearchTopic(id: ResearchTopicId): ResearchTopic {
  const topic = RESEARCH_TOPICS.find((candidate) => candidate.id === id);
  if (!topic) throw new Error(`Unknown research topic: ${id}`);
  return topic;
}

export function getResearchTopicPlacement(
  post: CollectionEntry<"blog">,
  topicId: ResearchTopicId,
): ResearchTopicPlacement | undefined {
  const explicitPlacement = post.data.topicPlacements.find(
    (placement: ResearchTopicPlacement) => placement.topic === topicId,
  );
  if (explicitPlacement) return explicitPlacement;

  if (post.data.topic === topicId && post.data.track && post.data.seriesOrder) {
    return {
      topic: topicId,
      track: post.data.track,
      order: post.data.seriesOrder,
    };
  }

  return undefined;
}

export function getResearchTopicPosts(
  posts: CollectionEntry<"blog">[],
  topicId: ResearchTopicId,
): CollectionEntry<"blog">[] {
  return posts
    .filter(
      (post) =>
        Boolean(getResearchTopicPlacement(post, topicId)) &&
        post.data.locale === "en" &&
        !post.data.draft,
    )
    .sort((a, b) => {
      const aPlacement = getResearchTopicPlacement(a, topicId);
      const bPlacement = getResearchTopicPlacement(b, topicId);
      return (
        (aPlacement?.order ?? Number.MAX_SAFE_INTEGER) -
          (bPlacement?.order ?? Number.MAX_SAFE_INTEGER) ||
        a.data.title.localeCompare(b.data.title, "en")
      );
    });
}

export function getTrackForPost(
  topic: ResearchTopic,
  post: CollectionEntry<"blog">,
): ResearchTrack | undefined {
  const placement = getResearchTopicPlacement(post, topic.id);
  return topic.tracks.find((track) => track.id === placement?.track);
}
