export interface NavItem {
  href: string;
  labelKey: string;
  icon?: string;
  external?: boolean;
  children?: NavItem[];
}

export const mainNav: NavItem[] = [
  { href: "/", labelKey: "nav.learn" },
  {
    href: "/topics/",
    labelKey: "nav.topics",
    children: [
      {
        href: "/topics/windows-privesc/",
        labelKey: "nav.windowsPrivesc",
      },
      { href: "/topics/malware-c2/", labelKey: "nav.malwareC2" },
      {
        href: "/topics/windows-internals/",
        labelKey: "nav.windowsInternals",
      },
    ],
  },
  {
    href: "/windows-service-vulnerabilities/",
    labelKey: "nav.vulnerabilities",
  },
  {
    href: "/windows-security-concepts/",
    labelKey: "nav.reference",
    children: [
      {
        href: "/windows-security-concepts/",
        labelKey: "nav.conceptHandbook",
      },
      {
        href: "/windows-service-vulnerabilities/",
        labelKey: "nav.windowsServiceAtlas",
      },
    ],
  },
  {
    href: "/windows-security-concepts/research-evidence/",
    labelKey: "nav.researchPractice",
  },
] as const;

export const footerNav = {
  product: [] as const,
  legal: [] as const,
  social: [
    {
      href: "https://github.com/kwpwn",
      labelKey: "footer.github",
    },
  ] as const,
} as const;

export function getFooterNav(section: keyof typeof footerNav): NavItem[] {
  return footerNav[section] as unknown as NavItem[];
}
