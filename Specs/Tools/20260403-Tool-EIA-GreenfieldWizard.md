# EIA Greenfield Wizard — Technical Specification

## Document Information
- **Specification Version:** 0.1 (Draft)
- **Date:** 2026-04-03
- **Status:** Draft — In Discussion
- **Tool Name:** EIA Greenfield Wizard
- **Output:** `policies.csv` + `security_profiles.csv` ready for `Start-EntraInternetAccessProvisioning`

---

## Overview

The EIA Greenfield Wizard is a static web-based tool that guides security/IT administrators through the creation of Entra Internet Access (EIA) web content filtering configuration from scratch — without requiring prior knowledge of the EIA CSV schema, Graph API, or the ~70 EIA web category names.

The wizard collects intent ("Finance users should not access social media or gambling sites") through a simple persona-based UI, then generates the two CSV files that `Start-EntraInternetAccessProvisioning` accepts directly.

### Problem Statement

The greenfield provisioning path requires creating two hand-crafted CSV files (`policies.csv` and `security_profiles.csv`). This demands knowledge of:
- EIA object model (policy → rules → profile → CA policy dependency chain)
- EIA web category names (PascalCase identifiers, ~70 entries)
- Priority numbering semantics
- The difference between "allow all except" and "block all except" in a block-only policy model

These barriers slow down POC deployments and onboarding. The wizard eliminates them.

### Target Audience
- IT Administrators and Security Administrators deploying EIA for the first time (POC or production)
- Microsoft SEs and partners walking customers through initial EIA deployment

### Design Principles
- **Zero backend** — pure static HTML/CSS/JS, no server required
- **Hosted on GitHub Pages** via the project's existing Docusaurus site (`website/`)
- **Output-first** — every interaction directly previews or updates the CSV output
- **Safe defaults** — the wizard pre-selects sensible configurations (Threat Intelligence enabled, sane priorities)
- **Learning tool** — labels and tooltips explain EIA concepts inline (e.g., what is a Security Profile)

---

## 1. Hosting and Delivery

### 1.1 Location in Repository
```
website/
  static/
    tools/
      greenfield-wizard.html   ← self-contained single file (MVP)
```

The file is served as-is by GitHub Pages / Docusaurus under a URL such as:
`https://<org>.github.io/Migrate2GSA/tools/greenfield-wizard`

### 1.2 Tech Stack
- **MVP:** Single self-contained `.html` file — vanilla HTML5, CSS, JavaScript. No build step, no npm, no framework dependency.
- **V2 (optional):** Migrate to a Docusaurus React page for better nav integration.

### 1.3 Browser Support
Modern evergreen browsers (Chrome, Edge, Firefox, Safari). No IE support required.

---

## 2. Conceptual Model — How Personas Map to EIA Objects

Understanding this mapping is critical to generating correct CSV output.

### 2.1 One Persona = One Security Profile + One (or more) Filtering Policies

Each persona the user defines produces:
- **One Filtering Policy** (block type, web category rules) in `policies.csv`
- **One Security Profile** that links that policy in `security_profiles.csv`
- Optionally, a **Conditional Access Policy** display name in `security_profiles.csv` (V2)

The Threat Intelligence system policy ("Block Malicious Destinations") is linked to every generated Security Profile by default — it is always present for baseline security.

### 2.2 The "Allow All Except" vs "Block All Except" Problem

EIA filtering policies have **a single action per policy: Block or Allow**. There is no "default block all" global setting — if no policy rule matches a request, traffic is implicitly allowed. This has an important consequence for the two filtering models:

#### Model A — "Allow all except [selected categories]" (simple)
The user selects which categories to **block**. This maps directly:
- → One **Block** policy, rule containing the selected category names.

**Example:** User selects `Gambling`, `SocialNetworking`, `Hacking`  
→ Block policy rule: `Gambling;SocialNetworking;Hacking`

#### Model B — "Block all except [selected categories]" (inverted)
The user selects which categories to **keep allowed**. To enforce this in EIA (which has no "block all" switch), the wizard must generate a Block policy containing **every EIA web category except the ones the user selected**.

- → One **Block** policy, rule containing `[ALL_CATEGORIES] - [user-selected categories]`.

**Example:** User selects `Business`, `Finance`, `Education` as the only allowed categories  
→ Block policy rule: all ~67 remaining categories

This is transparent to the administrator — the wizard performs the set complement automatically. The spec note is here to inform the implementation and to explain why the generated CSV may contain a long category list in this mode.

> **Open question:** Should the wizard warn the user when "Block all except" mode generates a policy with >50 categories, suggesting they review the list? This could help them discover EIA categories they overlooked.

### 2.3 Category Groups
The ~70 EIA web categories are organized into display groups in the UI (not a formal EIA concept — for UX only):

| Group | Categories |
|---|---|
| **Security & Risk** | ChildAbuseImages, CriminalActivity, Hacking, HateAndIntolerance, IllegalDrug, IllegalSoftware, Marijuana, SelfHarm, Violence, Weapons, Tasteless, CryptocurrencyMining, RemoteAccess, PornographyAndSexuallyExplicit, Nudity, LingerieAndSwimsuits, SexEducation, AlcoholAndTobacco, DatingAndPersonals, Gambling, Cheating, Cults |
| **Social & Communication** | Chat, InstantMessaging, SocialNetworking, WebBasedEmail, ForumsAndNewsgroups, PersonalSites, ProfessionalNetworking, WebMeetings, ImageSharing |
| **Entertainment & Leisure** | Entertainment, Games, Arts, FashionAndBeauty, LeisureAndRecreation, NatureAndConservation, RestaurantsAndDining, Sports, Travel, Shopping, StreamingMediaAndDownloads |
| **Productivity & Business** | Business, CodeRepositories, ComputersAndTechnology, Education, Finance, Government, HealthAndMedicine, JobSearch, News, NonProfitsAndNgos, SearchEnginesAndPortals, Translators, WebRepositoryAndStorage, DownloadSites, HostedPaymentGateways, RealEstate, Religion, Transportation, PoliticsAndLaw, ArtificialIntelligence |
| **Infrastructure** | PrivateIPAddresses, AdvertisementsAndPopUps, ParkedDomains, NewlyRegisteredDomains, Uncategorized, PeerToPeer, General |

---

## 3. Wizard User Flow (MVP)

### Step 1 — Introduction Screen
- Brief explanation of what the wizard produces
- "What you'll get: two CSV files ready to provision EIA filtering policies and security profiles"
- Link to `Start-EntraInternetAccessProvisioning` docs
- [ Begin ] button

### Step 2 — Define Personas
The main working screen. Displays a table of personas defined so far.

**Persona table columns:**
| # | Persona Name | Filtering Model | Categories Selected | Preview | Actions |
|---|---|---|---|---|---|
| 1 | Finance | Block all except | 4 allowed | [View] | [Edit] [Remove] |
| 2 | Marketing | Allow all except | 6 blocked | [View] | [Edit] [Remove] |

**Controls:**
- [ + Add Persona ] button → opens the persona editor panel
- [ Download policies.csv ] (disabled until at least one persona exists)
- [ Download security_profiles.csv ] (disabled until at least one persona exists)

### Step 3 — Persona Editor (modal or side panel)
Fields:
1. **Persona Name** (text input, required) — free text, becomes the base name for generated objects
   - Validation: no special characters except `-` and `_`; must be unique across personas
2. **Filtering Model** (radio):
   - ◉ "Allow all, block exceptions" ← default, recommended
   - ○ "Block all, allow exceptions"
3. **Category Picker** — grouped accordion/checkbox panel
   - Groups collapsed by default, expand on click
   - "Select all in group" checkbox per group header
   - Selected count shown per group
   - Label for each category shows its display name (not the PascalCase ID)
4. **Summary bar** (live update):
   - Model A: "X categories will be **blocked**"
   - Model B: "X categories will be **allowed** — Y will be **blocked**"
     - Warning if Y > 50: "This will generate a long category list. Consider reviewing the blocked categories."
5. [ Save Persona ] / [ Cancel ]

### Step 4 — Export
When user clicks "Download policies.csv" or "Download security_profiles.csv":
- File is generated in-browser (Blob + anchor download)
- Filename includes a timestamp: `{YYYYMMDD}_HHMMSS_EIA_Policies.csv`
- A preview table is shown inline before download (collapsible)

---

## 4. CSV Output Specification

### 4.1 Policies CSV
Column order must match `Start-EntraInternetAccessProvisioning` expectations:
`PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision`

**Generation rules per persona:**

| Field | Value |
|---|---|
| `PolicyName` | `{PersonaName}-Block` |
| `PolicyType` | `WebContentFiltering` |
| `PolicyAction` | `Block` |
| `Description` | `Generated by EIA Greenfield Wizard — {Model description}` |
| `RuleType` | `webCategory` |
| `RuleDestinations` | Semicolon-separated list of EIA category names (see §2.2) |
| `RuleName` | `{PersonaName}-BlockedCategories` |
| `Provision` | `yes` |

One row per persona in MVP (single webCategory rule per policy). FQDN rules are a V2 addition.

### 4.2 Security Profiles CSV
Column order: `SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision`

**Generation rules per persona:**

| Field | Value |
|---|---|
| `SecurityProfileName` | `Profile_{PersonaName}` |
| `Priority` | Auto-assigned: 100, 200, 300… in persona creation order |
| `SecurityProfileLinks` | `{PersonaName}-Block:100` (policy link at priority 100) |
| `CADisplayName` | *(empty in MVP — V2)* |
| `EntraUsers` | *(empty in MVP — V2)* |
| `EntraGroups` | *(empty in MVP — V2)* |
| `Provision` | `yes` |

> **Note:** Threat Intelligence ("Block Malicious Destinations") linking is handled at provisioning time by `Start-EntraInternetAccessProvisioning` if the user opts in via a separate parameter. The wizard does not need to add it to the CSV explicitly in MVP.

> **Open question:** Should the wizard offer a toggle to include the Threat Intelligence policy link in `SecurityProfileLinks`? This would require knowing the exact policy name that `Start-EntraInternetAccessProvisioning` expects for that link type (no-priority format per the spec).

### 4.3 Naming Conventions

| Object | Pattern | Example |
|---|---|---|
| Filtering Policy | `{PersonaName}-Block` | `Finance-Block` |
| Policy Rule | `{PersonaName}-BlockedCategories` | `Finance-BlockedCategories` |
| Security Profile | `Profile_{PersonaName}` | `Profile_Finance` |
| CA Policy (V2) | `CA_GSA_{PersonaName}` | `CA_GSA_Finance` |

---

## 5. Scope Boundaries

### 5.1 In Scope — MVP (V1)
- [x] Persona creation with free-form name
- [x] "Allow all except" and "Block all except" filtering models
- [x] Web category selection (grouped, with select-all per group)
- [x] Generation of `policies.csv` and `security_profiles.csv`
- [x] Browser-side CSV download (no server)
- [x] Inline preview of generated CSV rows
- [x] Hosted as a static file in `website/static/tools/`

### 5.2 Out of Scope — MVP (deferred to V2+)
- [ ] FQDN / URL exceptions per persona (allow/block specific sites)
- [ ] TLS Inspection policy generation
- [ ] CA policy assignment (Entra users/groups input)
- [ ] Entra group name validation (requires tenant connection)
- [ ] Import / load existing CSV for editing
- [ ] Multiple block policies per persona (advanced layering)
- [ ] Baseline profile (shared policies that apply to all personas)
- [ ] Persona priority reordering (drag and drop)

---

## 6. Open Questions / Decisions Pending

| # | Question | Options | Status |
|---|---|---|---|
| OQ-1 | Warn user when "Block all except" generates >50 category rule? | Yes / No | **Open** |
| OQ-2 | Include Threat Intelligence link toggle in wizard? | Yes (add to SecurityProfileLinks) / No (handle at provisioning time) | **Open** |
| OQ-3 | One rule per group vs. one combined rule? Consider splitting category list into per-group rules for readability | Single combined rule (MVP) / One rule per UI group | **Open** |
| OQ-4 | Filename convention for download: timestamp prefix or user-defined? | Timestamp (matches existing file naming in project) / user-defined | **Proposed:** timestamp |
| OQ-5 | Where to link the wizard from the Docusaurus site? Sidebar, getting-started page, or both? | Both | **Open** |
| OQ-6 | Should "Block all except" model be presented first or second to avoid steering admins toward the more complex model? | Place "Allow all except" first and recommend it | **Proposed** |

---

## 7. Future Considerations (Not Specced)

- **AI-assisted mode:** A Copilot agent variant that accepts natural language (e.g., "Finance users should be able to access banking sites but not personal email or social media") and maps it to category selections. This would reuse this wizard's output format and could be layered on top.
- **Baseline profile:** A shared "everyone" profile (Security_Threats-Block baseline) that applies to all users, with persona-specific profiles layered on top. The wizard could generate this automatically as the lowest-priority profile.
- **Import round-trip:** Load an existing `policies.csv` back into the wizard for visual editing, then re-export.
