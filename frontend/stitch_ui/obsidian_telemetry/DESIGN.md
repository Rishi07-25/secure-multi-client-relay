---
name: Obsidian Telemetry
colors:
  surface: '#121315'
  surface-dim: '#121315'
  surface-bright: '#38393b'
  surface-container-lowest: '#0d0e10'
  surface-container-low: '#1b1c1e'
  surface-container: '#1f2022'
  surface-container-high: '#292a2c'
  surface-container-highest: '#343537'
  on-surface: '#e3e2e5'
  on-surface-variant: '#c3c6d7'
  inverse-surface: '#e3e2e5'
  inverse-on-surface: '#303033'
  outline: '#8d90a0'
  outline-variant: '#434655'
  surface-tint: '#b4c5ff'
  primary: '#b4c5ff'
  on-primary: '#002a78'
  primary-container: '#2563eb'
  on-primary-container: '#eeefff'
  inverse-primary: '#0053db'
  secondary: '#4edea3'
  on-secondary: '#003824'
  secondary-container: '#00a572'
  on-secondary-container: '#00311f'
  tertiary: '#ffb95f'
  on-tertiary: '#472a00'
  tertiary-container: '#996100'
  on-tertiary-container: '#ffeedd'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#dbe1ff'
  primary-fixed-dim: '#b4c5ff'
  on-primary-fixed: '#00174b'
  on-primary-fixed-variant: '#003ea8'
  secondary-fixed: '#6ffbbe'
  secondary-fixed-dim: '#4edea3'
  on-secondary-fixed: '#002113'
  on-secondary-fixed-variant: '#005236'
  tertiary-fixed: '#ffddb8'
  tertiary-fixed-dim: '#ffb95f'
  on-tertiary-fixed: '#2a1700'
  on-tertiary-fixed-variant: '#653e00'
  background: '#121315'
  on-background: '#e3e2e5'
  surface-variant: '#343537'
typography:
  headline-xl:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 38px
    letterSpacing: -0.025em
  headline-lg:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 30px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Geist
    fontSize: 18px
    fontWeight: '500'
    lineHeight: 24px
    letterSpacing: -0.015em
  body-lg:
    fontFamily: Geist
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 22px
    letterSpacing: -0.01em
  body-md:
    fontFamily: Geist
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
    letterSpacing: -0.005em
  body-sm:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: 0em
  mono-lg:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 18px
    letterSpacing: -0.01em
  mono-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: 0em
  mono-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 14px
    letterSpacing: 0.02em
  label-md:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.01em
  label-sm:
    fontFamily: Geist
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 14px
    letterSpacing: 0.02em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-dense: 0.5rem
  margin: 1.5rem
  margin-compact: 1rem
  space-2xs: 0.125rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
  space-2xl: 2rem
---

## Brand & Style

This design system targets SecOps engineers, incident responders, infrastructure architects, and red/blue teams navigating complex threat landscapes. The system prioritizes quiet precision, operational trust, and hyper-legible telemetry over visual spectacle. 

The aesthetic is built on high-density utility: deliberate, utilitarian minimalism infused with terminal-grade precision. It avoids the visual cliches of cybersecurity—no gratuitous glowing wireframes, no neon-drenched cyber-hues, and no rounded, pill-heavy playfulness. Every pixel communicates situational awareness. Space, subtle contrast, and structural 1px dividers serve as primary organizational mechanisms, creating an interface that feels like high-end professional hardware: calm under crisis, razor-sharp, and unyielding in its density and speed.

## Colors

The palette operates in strict darkness. The baseline environment utilizes pitch-graphite tiers (`#090a0c` canvas, `#0d0f12` sidebars, `#12151a` panels, and `#15181e` elevated surfaces). Structure is maintained through restrained hairlines (`#222730` subtle, `#2b323d` focused).

Color is functional and scarce:
- **Primary Cobalt (`#2563eb` / `#3b82f6`):** Dedicated exclusively to focused states, primary action execution, and selected active tabs. It must never be used across large decorative backgrounds.
- **Telemetry Indicators:** Semantic colors are reserved for literal status:
  - **Operational (`#10b981`):** Active sockets, running daemons, safe state pings.
  - **Degraded/Warning (`#f59e0b`):** Packet drops, unverified signatures, threshold warnings.
  - **Critical/Incident (`#ef4444`):** Breach signatures, blocked vectors, dead nodes.
- **Typography Neutrals:** Primary high-contrast text (`#f3f4f6`), secondary data labels (`#9ca3af`), and structural tertiary metadata (`#64748b`).

## Typography

The type system implements a dual-engine architecture:
- **Interface & System Layer (Geist):** Handles UI chrome, navigation, headers, form controls, and status summaries. Letter tracking is slightly negative in headings to retain density and authority.
- **Telemetry & Data Layer (JetBrains Mono):** Mandated for tabular logs, IPv4/IPv6 addresses, payload hashes, packet counters, latency statistics, and sequence identifiers. Tabular lining numbers must be strictly preserved across all data points to eliminate visual jitter during real-time stream updates.

Font scaling emphasizes compact density over expansive display sizing, preventing telemetry truncation on high-resolution multi-monitor monitoring stations.

## Layout & Spacing

Layouts follow an edge-to-edge docking model divided by explicit 1px rules rather than island-based visual margins. 

The console operates on a collapsible 3-pane orchestration:
1. **Command Rail / Workspace Selector:** Fixed 56px–64px width.
2. **Context Inspector / Resource Tree:** Flexible or pinned 280px–360px panel.
3. **Primary Operation Canvas & Telemetry Stream:** Dynamic 12-column fluid grid scaling continuously.

For data grids and execution logs, spacing collapses to `space-xs` and `space-sm` vertically to maximize vertical scan length without scrolling. Margins on the viewport perimeter remain strictly anchored at `margin` (24px) for desktop viewports, dropping to `margin-compact` (16px) under tablet/breakout contexts. Mobile refactors stack panels into vertical sliding drawers with tab-swapped telemetry consoles.

## Elevation & Depth

Visual hierarchy is maintained through precise tonal stacking and 1px hairline perimeter borders. Layered shadows are suppressed in favor of structural opacity tiers:

- **Base Environment (L0):** `#090a0c` canvas. Zero shadow.
- **Docked Panels & Navigation (L1):** `#0d0f12` background, separated by a `1px solid #222730` hairline.
- **Focused Containers & Data Tables (L2):** `#12151a` background with `1px solid #222730` stroke. Hover states subtly lift the border to `#2b323d`.
- **Command Palettes, Popovers & Context Menus (L3):** `#15181e` surface fill, `1px solid #2b323d` border, reinforced by an ambient shadow (`0 12px 32px -4px rgba(0, 0, 0, 0.75)`).

No blurred colored backdrops or glowing neon contours are permitted. Highlighting is achieved through direct pixel boundaries and crisp inner-stroke highlights (`inset 0 1px 0 0 rgba(255, 255, 255, 0.05)`).

## Shapes

The geometry is restrained, industrial, and sharp. All buttons, inputs, badge frames, and modal frames use subtle 4px corner radii (`0.25rem`), advancing to 6px (`0.375rem`) for viewport-level popovers and detached context sheets. Circular forms are strictly reserved for 6px status pings, avatar chips, and radio selectors. Sharp cornering reinforces systemic authority and seamless border docking between horizontal and vertical panes.

## Components

### Buttons & Action Controls
- **Primary:** `#2563eb` solid background, `#ffffff` text, subtle top highlight (`inset 0 1px 0 0 rgba(255, 255, 255, 0.2)`), hover `#1d4ed8`. Height: 28px (compact) / 32px (standard). 
- **Secondary / Ghost:** Transparent or `#12151a` fill, `1px solid #222730` border, `#f3f4f6` text. Hover: `#15181e` background, `#2b323d` border.
- **Destructive:** `#12151a` background, `1px solid rgba(239, 68, 68, 0.3)` border, `#ef4444` text. Hover: `#ef4444` fill, `#ffffff` text.

### Telemetry Tables & Log Rows
- Compact row height (28px to 32px), bordered with bottom hairlines (`#1a1f26`).
- No zebra striping; active row scanning relies on a subtle `#15181e` hover state.
- Column headers: JetBrains Mono, 11px, uppercase, `#64748b` text with inline sort indicators.

### Status Indicators & Badges
- Badges use muted fills (`rgba(color, 0.08)`), matching `1px` subtle borders (`rgba(color, 0.2)`), and high-legibility label text.
- Live status indicators use a literal 6px circular dot with no blur glow, accompanied by an optional ping animation for active threat triage.

### Inputs & Command Bars
- Inset dark background (`#090a0c`), `1px solid #222730` border, 32px height. Focus transitions the border to `#2563eb` with an unobtrusive `0 0 0 1px #2563eb` outline.
- Monospace keyboard accelerators (`⌘K`, `ESC`) rendered as discrete secondary keycaps (`#15181e` background, `#2b323d` border).

### Checkboxes & Segmented Controls
- Checkboxes: 14px × 14px square, 2px radius, `#12151a` fill, `#222730` border. Active state: `#2563eb` fill with a white checkmark.
- Segmented Rail: `#0d0f12` container holding 24px sliding tabs; active tab styled with `#15181e` background and `1px solid #2b323d`.