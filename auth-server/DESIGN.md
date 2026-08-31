# Wise SSO Design System

## 1. Atmosphere & Identity

Wise SSO follows the TEMIS welcome surface: a dark navy authentication console with a precise centered form panel, restrained blue accents, thin borders, and minimal operational copy.

## 2. Color

| Role | Token | Light | Usage |
|------|-------|-------|-------|
| Surface primary | `--surface-primary` | `#0f1622` | Page background |
| Surface deeper | `--surface-deeper` | `#080d17` | Lower page gradient |
| Surface panel | `--surface-panel` | `#151b26` | Form panel |
| Surface panel strong | `--surface-panel-strong` | `#1d2533` | Hover surface |
| Surface muted | `--surface-muted` | `#11161f` | Inputs and secondary buttons |
| Text primary | `--text-primary` | `#f1f5f9` | Headings and body |
| Text secondary | `--text-secondary` | `#cbd5e1` | Supporting copy |
| Text muted | `--text-muted` | `#64748b` | Helper text |
| Border default | `--border-default` | `#232d3f` | Inputs and panels |
| Border strong | `--border-strong` | `#334155` | Focus and hover outlines |
| Accent primary | `--accent-primary` | `#3b82f6` | Primary actions |
| Accent hover | `--accent-hover` | `#2563eb` | Primary hover |
| Accent soft | `--accent-soft` | `rgb(59 130 246 / 0.12)` | Notice and soft selected states |
| Status success | `--status-success` | `#34d399` | Success messages |
| Status error | `--status-error` | `#fb7185` | Error messages |

Rules:
- Accent appears only on interactive controls, focus rings, and status accents.
- Dark panels use thin borders, subtle top highlights, and black shadow for depth.
- Avoid light SaaS cards and green-first palette drift.

## 3. Typography

| Level | Size | Weight | Line Height | Tracking | Usage |
|-------|------|--------|-------------|----------|-------|
| H1 | 32px | 700 | 1.2 | 0 | Page title |
| H2 | 22px | 650 | 1.3 | 0 | Form heading |
| Body | 16px | 400 | 1.6 | 0 | Default text |
| Body small | 14px | 400 | 1.5 | 0 | Help and links |
| Label | 13px | 650 | 1.4 | 0 | Form labels |

Font stack:
- Primary: Inter, system UI, Apple SD Gothic Neo, Segoe UI, sans-serif
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
- Auth shell max width: 480px.
- Desktop and mobile: single centered form panel.

## 5. Components

### Auth Shell
- Structure: centered `main` with one form panel.
- States: responsive centered panel.
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

### Admin Dashboard
- Structure: full-width operational workspace with a compact token panel, filter toolbar, user table, and detail drawer.
- States: empty, loading, unauthorized, selected row, mutation pending.
- Accessibility: semantic table, labelled filters, visible focus, button text that names the action.
- Security: admin access token is held only in `sessionStorage`; refresh tokens are never accepted in this UI.

### Data Table
- Structure: header row, dense rows, status badges, role chips, action buttons.
- States: loading skeleton text, empty result, selected row, overflow on narrow screens.
- Accessibility: `table` semantics on desktop; horizontal scroll instead of clipped cells.

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
| Panel shadow | `0 22px 60px rgb(0 0 0 / 0.35)` | Form panel |
| Soft border | `1px solid var(--border-default)` | Inputs and panels |
| Focus ring | `0 0 0 3px rgb(59 130 246 / 0.28)` | Inputs and buttons |
