# Wise SSO Design System

## 1. Atmosphere & Identity

Wise SSO is a quiet authentication console for company services. The signature is a calm split workspace: a precise form surface beside a restrained trust panel, using green-blue accents to signal secure access without decorative noise.

## 2. Color

| Role | Token | Light | Usage |
|------|-------|-------|-------|
| Surface primary | `--surface-primary` | `#f7f9fb` | Page background |
| Surface panel | `--surface-panel` | `#ffffff` | Form panels |
| Surface muted | `--surface-muted` | `#eef4f3` | Trust panel |
| Text primary | `--text-primary` | `#10201d` | Headings and body |
| Text secondary | `--text-secondary` | `#52625f` | Supporting copy |
| Text muted | `--text-muted` | `#74817f` | Helper text |
| Border default | `--border-default` | `#d8e1df` | Inputs and panels |
| Border strong | `--border-strong` | `#b8c7c4` | Focus outlines |
| Accent primary | `--accent-primary` | `#107c72` | Primary actions |
| Accent hover | `--accent-hover` | `#0b665e` | Primary hover |
| Accent soft | `--accent-soft` | `#dff1ee` | Soft selected states |
| Status success | `--status-success` | `#167a4a` | Success messages |
| Status error | `--status-error` | `#bd2f2f` | Error messages |

Rules:
- Accent appears only on interactive controls and status accents.
- White panels use borders and light shadow together for legibility.
- No purple-blue gradient palette.

## 3. Typography

| Level | Size | Weight | Line Height | Tracking | Usage |
|-------|------|--------|-------------|----------|-------|
| H1 | 32px | 700 | 1.2 | 0 | Page title |
| H2 | 22px | 650 | 1.3 | 0 | Form heading |
| Body | 16px | 400 | 1.6 | 0 | Default text |
| Body small | 14px | 400 | 1.5 | 0 | Help and links |
| Label | 13px | 650 | 1.4 | 0 | Form labels |

Font stack:
- Primary: system UI, Apple SD Gothic Neo, Segoe UI, sans-serif
- Mono: ui-monospace, SFMono-Regular, Menlo, monospace

## 4. Spacing & Layout

Base unit: 4px.

| Token | Value | Usage |
|-------|-------|-------|
| `--space-2` | 8px | Inline gaps |
| `--space-3` | 12px | Field groups |
| `--space-4` | 16px | Compact panel padding |
| `--space-6` | 24px | Form section spacing |
| `--space-8` | 32px | Panel spacing |
| `--space-10` | 40px | Page gutters |
| `--space-12` | 48px | Desktop panel padding |

Layout:
- Auth shell max width: 1040px.
- Desktop: two columns, form first, trust panel second.
- Mobile: single column, form first, trust panel below.

## 5. Components

### Auth Shell
- Structure: centered `main` with form panel and trust panel.
- States: mobile stacked, desktop split.
- Accessibility: `main` landmark and single visible `h1`.

### Form Field
- Structure: label, input, optional helper text.
- States: default, hover, focus, invalid, disabled.
- Accessibility: visible labels, browser validation, focus ring.

### Button
- Variants: primary, secondary, text link.
- States: default, hover, active, focus, loading, disabled.
- Accessibility: native button or anchor according to behavior.

### Notice
- Variants: success, error, neutral.
- States: hidden, visible.
- Accessibility: `role="status"` for success, `role="alert"` for errors.

## 6. Motion & Interaction

Timing:
- Micro: 120ms ease-out for button and input feedback.
- Standard: 180ms ease-in-out for notices.

Rules:
- Animate only opacity and transform.
- Respect `prefers-reduced-motion`.
- No decorative looping motion.

## 7. Depth & Surface

Strategy: mixed.

| Level | Value | Usage |
|-------|-------|-------|
| Panel shadow | `0 18px 48px rgb(16 32 29 / 0.10)` | Form panel |
| Soft border | `1px solid var(--border-default)` | Inputs and panels |
| Focus ring | `0 0 0 3px rgb(16 124 114 / 0.18)` | Inputs and buttons |
