export interface NavItem {
  href: string;
  labelKey: string;
  icon?: string;
  external?: boolean;
  children?: NavItem[];
}

export const mainNav: NavItem[] = [
  { href: "/", labelKey: "nav.home" },
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
    href: "/windows-security-concepts/",
    labelKey: "nav.windowsSecurityConcepts",
  },
  {
    href: "/windows-service-vulnerabilities/",
    labelKey: "nav.windowsServiceAtlas",
  },
  { href: "/blogs/", labelKey: "nav.blogs" },
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
