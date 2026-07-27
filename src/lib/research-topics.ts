import type { CollectionEntry } from "astro:content";

export const RESEARCH_TOPIC_IDS = [
  "windows-privesc",
  "malware-c2",
  "windows-internals",
] as const;

export type ResearchTopicId = (typeof RESEARCH_TOPIC_IDS)[number];
export type ResearchTrackId =
  | "foundations"
  | "privilege-boundaries"
  | "execution"
  | "analysis"
  | "telemetry"
  | "kernel-boundaries";

export interface ResearchTrack {
  id: ResearchTrackId;
  label: string;
  description: string;
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
      "Build escalation chains from evidence: identify the actor, prove control over a privileged input, follow the execution boundary, and validate the resulting security context.",
    question:
      "Which low-privileged control can influence code, data, identity, or configuration consumed by a more privileged Windows component?",
    outcome:
      "You will be able to distinguish an interesting permission from a complete, reproducible escalation path.",
    icon: "lucide:shield-alert",
    recommendedStart: "windows-privesc-trust-boundary-model",
    yunolayUrl: "https://yunolay.com/category/windows-privesc/",
    tracks: [
      {
        id: "foundations",
        label: "Security model",
        description:
          "Tokens, SIDs, integrity levels, privileges, security descriptors, and the access decision.",
      },
      {
        id: "privilege-boundaries",
        label: "Privileged executors",
        description:
          "Services, scheduled tasks, installers, and other components that cross a user-to-SYSTEM boundary.",
      },
      {
        id: "execution",
        label: "Load and execution paths",
        description:
          "Binary paths, DLL resolution, registry-controlled loading, and file-system control.",
      },
      {
        id: "analysis",
        label: "Validation workflow",
        description:
          "Turn enumeration into a version-aware claim with a safe lab, negative controls, and remediation evidence.",
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
      "Study malicious software as an observable system: file structure, execution state, persistence, tasking, transport, and the telemetry each transition leaves behind.",
    question:
      "What state changed, which component caused it, how did data move, and which independent sensor can confirm the story?",
    outcome:
      "You will be able to analyze behavior and C2 design without relying on signatures or opaque tool output.",
    icon: "lucide:radio-tower",
    recommendedStart: "malware-c2-execution-tasking-telemetry-model",
    yunolayUrl: "https://yunolay.com/category/malware-c2/",
    tracks: [
      {
        id: "foundations",
        label: "Behavior model",
        description:
          "Execution stages, capabilities, state transitions, tasking, results, and evidence quality.",
      },
      {
        id: "analysis",
        label: "Static and dynamic analysis",
        description:
          "PE structure, imports, strings, runtime changes, controlled networking, and reproducible timelines.",
      },
      {
        id: "execution",
        label: "Controlled execution",
        description:
          "Contained labs, process relationships, runtime state changes, memory permissions, and evidence-preserving execution.",
      },
      {
        id: "telemetry",
        label: "C2 and detection",
        description:
          "Protocol semantics, task queues, timing, identity, network metadata, ETW, Sysmon, and correlation.",
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
      "Connect documented Win32 behavior to the executive objects, trust decisions, system-call boundary, and I/O machinery that implement it.",
    question:
      "Which object owns the state, which reference keeps it alive, which boundary validates the request, and where does the result return?",
    outcome:
      "You will be able to explain Windows behavior as a chain of objects and transitions rather than a list of isolated structures.",
    icon: "lucide:cpu",
    recommendedStart: "windows-process-thread-token-handle-model",
    yunolayUrl: "https://yunolay.com/category/windows-internals/",
    tracks: [
      {
        id: "foundations",
        label: "Processes and execution",
        description:
          "Processes as resource containers, threads as schedulable execution, tokens as security context, and handles as references.",
      },
      {
        id: "privilege-boundaries",
        label: "Objects and security",
        description:
          "Object namespaces, object types, handle tables, security descriptors, access masks, and lifetime.",
      },
      {
        id: "kernel-boundaries",
        label: "System-call boundary",
        description:
          "User-to-kernel transitions, Nt and Zw behavior, PreviousMode, parameter trust, and WOW64.",
      },
      {
        id: "execution",
        label: "I/O and drivers",
        description:
          "Device stacks, IRPs, IOCTL access bits, buffering methods, completion, and cancellation.",
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

export function getResearchTopicPosts(
  posts: CollectionEntry<"blog">[],
  topicId: ResearchTopicId,
): CollectionEntry<"blog">[] {
  return posts
    .filter(
      (post) =>
        post.data.topic === topicId &&
        post.data.locale === "en" &&
        !post.data.draft,
    )
    .sort(
      (a, b) =>
        (a.data.seriesOrder ?? Number.MAX_SAFE_INTEGER) -
          (b.data.seriesOrder ?? Number.MAX_SAFE_INTEGER) ||
        a.data.title.localeCompare(b.data.title, "en"),
    );
}

export function getTrackForPost(
  topic: ResearchTopic,
  post: CollectionEntry<"blog">,
): ResearchTrack | undefined {
  return topic.tracks.find((track) => track.id === post.data.track);
}
