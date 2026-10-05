---
name: Obsidian Relay Security Console
colors:
  surface: '#051424'
  surface-dim: '#051424'
  surface-bright: '#2c3a4c'
  surface-container-lowest: '#010f1f'
  surface-container-low: '#0d1c2d'
  surface-container: '#122131'
  surface-container-high: '#1c2b3c'
  surface-container-highest: '#273647'
  on-surface: '#d4e4fa'
  on-surface-variant: '#bec8d2'
  inverse-surface: '#d4e4fa'
  inverse-on-surface: '#233143'
  outline: '#88929b'
  outline-variant: '#3e4850'
  surface-tint: '#89ceff'
  primary: '#89ceff'
  on-primary: '#00344d'
  primary-container: '#0ea5e9'
  on-primary-container: '#003751'
  inverse-primary: '#006591'
  secondary: '#4edea3'
  on-secondary: '#003824'
  secondary-container: '#00a572'
  on-secondary-container: '#00311f'
  tertiary: '#ffb95f'
  on-tertiary: '#472a00'
  tertiary-container: '#d88a00'
  on-tertiary-container: '#4a2c00'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#c9e6ff'
  primary-fixed-dim: '#89ceff'
  on-primary-fixed: '#001e2f'
  on-primary-fixed-variant: '#004c6e'
  secondary-fixed: '#6ffbbe'
  secondary-fixed-dim: '#4edea3'
  on-secondary-fixed: '#002113'
  on-secondary-fixed-variant: '#005236'
  tertiary-fixed: '#ffddb8'
  tertiary-fixed-dim: '#ffb95f'
  on-tertiary-fixed: '#2a1700'
  on-tertiary-fixed-variant: '#653e00'
  background: '#051424'
  on-background: '#d4e4fa'
  surface-variant: '#273647'
typography:
  headline-xl:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.025em
  headline-lg:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Geist
    fontSize: 20px
    fontWeight: '500'
    lineHeight: 28px
    letterSpacing: -0.015em
  headline-sm:
    fontFamily: Geist
    fontSize: 16px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-lg:
    fontFamily: Geist
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Geist
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  code-lg:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: -0.01em
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 14px
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.05em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '600'
    lineHeight: 12px
    letterSpacing: 0.08em
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
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1.25rem
  space-xl: 2rem
---

## Brand & Style
This design system defines a high-assurance operations center interface engineered for critical cryptographic infrastructure and blind multi-client relays. The visual posture communicates unyielding precision, operational calm under duress, and rigorous technical control.

### Aesthetic Foundation
- **Tactical Utility over Decorative Novelty:** Eschew generic SaaS conventions, gradient washes, and juvenile gaming neons. Every element mirrors mission-critical security hardware consoles, high-density radar suites, and air-gapped terminal appliances.
- **Micro-Contrast & Structural Hierarchy:** Visual order is generated via calibrated panel tiers (#0B0F17 to #161F30), hairline division grids (#1E293B, #334155), and deliberate focus-directed light emittance rather than heavy DropShadow clutter.
- **Cryptographic Trust Indicators:** UI surfaces emphasize continuous verification, nonces, key digests, frame sequence integrity, and blind transport paths through structured terminal stamps and status indicators.

## Colors
The system relies on a calibrated dark-spectrum tonal palette optimized for multi-monitor NOC/SOC environments, preventing operator fatigue while providing rapid signal parsing.

### Core Canvas & Panel Tiers
- **Void Canvas (`#0B0F17`):** The absolute background anchor for all root layouts and unpaneled voids.
- **Base Console Tier (`#111827`):** Primary panel, sidebar, and container background.
- **Raised Elevation Surface (`#161F30`):** Secondary nested containers, inspection drawers, data tables, and input wells.
- **Structural Dividers & Outlines:**
  - `Surface Border / Subtle`: `#1E293B` (Used for standard panel perimeters and card boundaries).
  - `Surface Border / Focused`: `#334155` (Active panel focus, hover strokes, key separators).

### Operational Accents & States
- **Electric Relay Blue (`#0EA5E9`, Highlight `#38BDF8`):** Primary command accent, focused node paths, client connection handles, and interactive control triggers.
- **Terminal Emerald (`#10B981`, Highlight `#34D399`):** Cryptographic verification confirmed, relay pipe healthy, zero-loss telemetry, authenticated enclave.
- **Sequence Warning Amber (`#F59E0B`, Highlight `#FBBF24`):** Handshake retries, frame jitter, certificate expiration warning (< 48h), client rate limit approach.
- **Tactical Crimson (`#EF4444`, Highlight `#F87171`):** Cryptographic signature failure, unauthorized replay attempt, severed socket, compromised peer handshake.
- **Neutral Stack:** Text primary (`#F8FAFC`), Text secondary/meta (`#94A3B8`), Muted telemetry text (`#64748B`).

## Typography
Typographic discipline is divided strictly into two functional systems: Interface Navigation (`Geist`) and Machine Verification (`JetBrains Mono`).

### Font Hierarchy & Allocations
- **Geist (Interface Primary):** Used for panel titles, navigation labels, contextual dialogue, modal alerts, and general interface text. Set with tighter tracking at medium and heavy weights to preserve horizontal real estate in dense operational layouts.
- **JetBrains Mono (System Telemetry & Cryptography):** Mandated for all SHA-256 / Ed25519 public keys, packet frame IDs, IPv4/IPv6 addresses, nonces, throughput rates (`MB/s`), and relay route nodes. Ensures identical character pitch for vertically aligned data inspection.
- **Case Rules:** All `label-sm` and `label-md` tokens are rendered strictly in uppercase to indicate raw appliance status (e.g., `CIPHER: CHACHA20-POLY1305`, `RELAY-ONLINE`, `DRAINING`).

## Layout & Spacing
The layout model employs an engineering-grade high-density modular frame designed for responsive NOC operation consoles.

### Layout Mechanics
- **Grid Architecture:** Multi-column split grid (configurable 12 or 16-column) dynamic desktop viewport layout. Panels prioritize high visual information density over decorative empty space.
- **Docked Panel Partitions:** Operations screens are divided into fixed functional panes: Global Top Bar (48px fixed height), Node Topology Matrix (variable width canvas), Telemetry Stream Deck (collapsible 360px sidebar), and Cryptographic Inspector Drawer (collapsible bottom tray).
- **Responsive Adaptations:**
  - `Desktop (>= 1440px)`: Full multi-pane visualization with synchronized terminal inspector.
  - `Tablet / Diagnostic Portable (768px - 1439px)`: Sidebars collapse to icon/badge rails; telemetry converts to tabbed stacks.
  - `Mobile / Triage Emergency (< 768px)`: Single column pane stack; tabular layouts collapse into key-value data cards with horizontal scroll for raw payload hex dumps.

## Elevation & Depth
Depth is produced via subtle tonal stepping and 1px technical outlines, deliberately avoiding soft consumer drop shadows which cause visual fuzzing in low-light operations rooms.

### Elevation Architecture
- **Layer 0 (Canvas Base - `#0B0F17`):** Root background, global frame gutters.
- **Layer 1 (Subsystem Dock - `#111827`):** Primary persistent regions, node matrix viewport wrapper, sidebar hulls. Outline: `1px solid #1E293B`.
- **Layer 2 (Functional Modules - `#161F30`):** Interactive cards, encrypted stream rows, telemetry modules, inspector containers. Outline: `1px solid #1E293B`.
- **Layer 3 (Overlays, Flyouts & Modals - `#161F30`):** Ephemeral command palettes, node debug drawers. Outline: `1px solid #334155`. Shadow: `0 12px 32px -4px rgba(0, 0, 0, 0.65), 0 0 0 1px #334155`.

### Focus Glow Dynamics
Interactive elements, active client tunnels, and error nodes emit a sharp, controlled 4px perimeter luminous halo using alpha-blended tokens:
- Active Tunnel / Selected: `box-shadow: 0 0 0 1px #0EA5E9, 0 0 12px rgba(14, 165, 233, 0.25)`
- Verified Enclave / Online: `box-shadow: 0 0 0 1px #10B981, 0 0 8px rgba(16, 185, 129, 0.20)`
- Breach / Handshake Fail: `box-shadow: 0 0 0 1px #EF4444, 0 0 12px rgba(239, 68, 68, 0.30)`

## Shapes
Geometry is controlled, sharp-edged, and structural, reinforcing hardware-like instrumentation.

### Corner Radius System
- **Core Elements (0.25rem / 4px):** Checkboxes, status tags, telemetry chips, cryptographic token pill badges, code blocks.
- **Intermediate Components (0.5rem / 8px):** Action buttons, input fields, dropdown trigger buttons, tab items.
- **Panels & Modules (0.75rem / 12px):** Main operations cards, modal overlays, telemetry inspection frames.
- **No Pill / Circular Buttons:** Full pill borders (`rounded-full`) are prohibited for interactive controls to maintain a serious, non-playful silhouette. Circles are reserved exclusively for live status beacons and blind relay peer connection nodes.

## Components

### Buttons
- **Primary Command:** Background `#0EA5E9`, text `#0B0F17` (bold `Geist`), border `1px solid #38BDF8`. Hover: `#38BDF8` with cyan edge glow. Active: scale 0.99.
- **Secondary Operations:** Background `#161F30`, text `#F8FAFC`, border `1px solid #1E293B`. Hover: border `#334155`, text `#38BDF8`.
- **Destructive/Revoke:** Background `rgba(239, 68, 68, 0.1)`, text `#EF4444`, border `1px solid rgba(239, 68, 68, 0.3)`. Hover: Background `#EF4444`, text `#FFFFFF`.
- **Dimensions:** Compact 32px height for dense consoles; 40px height for primary triage modals.

### Input Fields & Terminal Selectors
- **Input Wells:** Background `#0B0F17`, border `1px solid #1E293B`, font `JetBrains Mono` 13px, text `#F8FAFC`. Placeholder `#64748B`.
- **States:** Focus produces `border-color: #0EA5E9` with a crisp `0 0 0 1px #0EA5E9`. Invalid cryptographic input switches border to `#EF4444`.
- **Prefix / Suffix Elements:** Static monochrome protocol tags (e.g., `wss://`, `ed25519:`) rendered in `#64748B` with `label-sm` specs.

### Cryptographic Status Chips & Relays
- **Structure:** 20px-24px height, padding `2px 8px`, `JetBrains Mono` 10px uppercase.
- **Verified State:** Border `1px solid rgba(16, 185, 129, 0.4)`, background `rgba(16, 185, 129, 0.08)`, text `#34D399`. Accompanied by a 6px solid `#10B981` status dot with an animated micro-pulse.
- **Blind Relay State:** Border `1px solid rgba(14, 165, 233, 0.4)`, background `rgba(14, 165, 233, 0.08)`, text `#38BDF8`.
- **Terminated / Revoked:** Border `1px solid rgba(239, 68, 68, 0.4)`, background `rgba(239, 68, 68, 0.08)`, text `#F87171`.

### Data Grids & Cryptographic Frame Lists
- **Header:** Background `#111827`, border-bottom `1px solid #334155`, text `JetBrains Mono` 11px uppercase `#94A3B8`.
- **Data Rows:** Background alternates `#111827` and `#0E1420`. Hover background `#161F30`. Border-bottom `1px solid #1E293B`.
- **Row Values:** Numeric and hash data tabularly aligned via monospaced sizing. Truncated hash strings display middle ellipsis (`0x4f92...a8b1`) and copy-on-click trigger with instant tooltip feedback.

### Blind-Relay Visual Node Cards
- Dedicated container cards displaying peer-to-peer relay tunnels.
- Contains dual terminal endpoints: `Client Origin [Blind ID]` linked via a dotted `#334155` technical trace line to `Relay Target Enclave`.
- Live connection pulse along the vector changes speed based on packet transit latency.