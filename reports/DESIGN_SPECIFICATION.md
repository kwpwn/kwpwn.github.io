# Design specification

## Product character

The interface is a calm technical library, not a security-product landing page.
Content, evidence state, and navigation hierarchy take precedence over
decoration. The system avoids neon, glass effects, ornamental icons, excessive
gradients, and cards around every section.

## Typography

- **Body and UI:** Source Sans 3 Variable with system and Segoe UI fallbacks.
- **Code:** JetBrains Mono Variable with Consolas and system-monospace
  fallbacks.
- **Long-form size:** approximately 16.5px on compact screens and 18px on
  desktop.
- **Long-form line height:** 1.72.
- **Reading measure:** 74ch; wide technical content may use 82ch.
- **Article title:** 28–36px.
- **General display heading ceiling:** 52px, with most library headings limited
  to the 34–44px token.
- **Weights:** normal body, semibold headings; bold is reserved for strong
  hierarchy and code/tool actions.

## Color

- Light background is a warm off-white, not pure white.
- Foreground is a warm near-charcoal, not black.
- Dark background is a dim warm charcoal, not black.
- One restrained blue accent identifies links, current location, and selected
  navigation.
- Note, warning, error, and success colors are semantic and must always include
  a text label.
- Dark mode swaps semantic tokens under the `.dark` class. Components never
  hand-invert colors.

Canonical values live in `src/styles/tokens/colors.css`.

## Spacing and layout

- Maximum documentation shell: 90rem.
- Article shell:
  - library navigation: 16rem;
  - main article allocation: up to 48rem;
  - table of contents: 13.5rem;
  - reading text itself: 74ch.
- Desktop uses left navigation, main content, and right TOC.
- Medium layouts collapse the library navigation to one disclosure row while
  retaining the TOC where space permits.
- Compact layouts use one column in this order: library disclosure, article
  header, TOC disclosure, article body.
- There is exactly one navigation tree and one TOC in the DOM.
- Borders indicate grouping; shadows are reserved for modal elevation.

Canonical values live in `src/styles/tokens/spacing.css`.

## Component rules

### Header

- Persistent and calm; it does not hide while scrolling.
- Primary destinations: Learn, Topics, Vulnerabilities, Reference, and Research
  practice.
- Search and theme controls retain text alternatives and visible focus.
- The mobile menu moves focus to its first link, closes on Escape, and restores
  focus to the trigger.

### Search

- Search opens with Ctrl+K or Cmd+K.
- Pagefind is loaded on demand.
- Results are grouped as Lessons, Concepts, CVEs, Services, Labs, and
  References.
- Excerpts preserve only text and `<mark>` highlighting from the local index.
- Arrow keys move through results; Escape closes the native modal.
- Header, footer, TOC, library navigation, previous/next, and related posts are
  excluded from indexing.

### Article header and evidence

- Show learning path, level, lesson order, title, description, author,
  publication/update date, and reading time.
- A separate research-status block shows content type, evidence state, Windows
  scope, and last reviewed date.
- Missing review or build data is rendered as “Not yet reviewed” or “Windows
  scope not yet verified.”
- “Confirmed” is never inferred from prose or a references list.

### Learning brief

- Render one “What you will learn” list, one prerequisite list, and one safe-lab
  boundary.
- The brief uses separators and whitespace rather than a stack of nested cards.

### Article body

- Headings receive stable fragment links.
- Code blocks receive a language label, copy control, and optional wrap control.
- Code scrolls horizontally by default.
- Tables retain horizontal scrolling on compact screens.
- Previous/next follows learning-path order.
- Lesson completion uses local storage and does not require an account.
- Print mode removes navigation, TOC, related cards, progress, and interactive
  controls.

### Browse pages

- Use task-oriented filters and bordered rows instead of card walls.
- Article rows expose path, content type, difficulty, review state, updated
  date, and reading time.
- Service metrics are a compact catalog snapshot, not promotional cards.
- Empty and unknown states use explicit text.

## Responsive behavior

| Width | Behavior |
| --- | --- |
| Above 1280px | Full three-region article shell. |
| 1024–1279px | Library navigation collapses; main and TOC remain side by side where readable. |
| Below 1024px | Single-column article flow; TOC and library navigation become disclosures. |
| Below 768px | Browse filters and metadata grids stack; touch targets remain at least the medium control height. |
| Below 480px | Secondary keyboard hints hide; content and controls remain fully labeled. |

## Accessibility rules

- WCAG 2.2 AA contrast for text and interactive states.
- One semantic `h1`; headings never skip levels in authored content.
- Visible `:focus-visible` on every interactive control.
- Native dialog for modal focus trapping.
- Escape and focus restoration for modal/menu interactions.
- Labels for every form control.
- No state communicated by color alone.
- Reduced-motion disables the decorative reading-progress indicator.
- Text selection remains enabled.
- Layout must remain usable at 200% zoom and without hover.

## Content presentation rules

- Technical claims use Documented fact, Observed behavior, Inference, or
  Hypothesis.
- Observation requires build, architecture, tool, procedure, and execution
  context.
- Claim-adjacent citations are preferred to a reference dump.
- Unknown, unverified, build-specific, and conflicting evidence are displayed
  plainly.
- Generic research methodology belongs in the central research-evidence
  concept, not repeated verbatim in every article.
