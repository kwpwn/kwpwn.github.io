export interface NavItem {
  href: string;
  labelKey: string;
  icon?: string;
  external?: boolean;
  children?: NavItem[];
}

export const mainNav: NavItem[] = [
  { href: "/", labelKey: "nav.home" },
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
