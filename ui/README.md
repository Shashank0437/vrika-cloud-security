# Description

This repository hosts the UI component for Prowler, providing a user-friendly web interface to interact seamlessly with Prowler's features.

## Vrika tracked findings

With `NEXT_PUBLIC_VRIKA_TRIAGE_ENABLED=true`, **Findings > Tracked findings &
history** opens `/findings/triage`. This view lists findings your team has changed
or annotated, including findings missing from current scans and resolved items.
It supports status/search filters, pagination, existing triage permissions, notes,
and audit history. Historical FAIL results remain clearly labeled even when the
workflow is resolved because a resource was removed.

The matching API requires migration `0101_triage_tracking` and the tracked-context
backfill described in `api/README.md`. Removal is not inferred by the UI. The API
initially verifies GCP Compute public-RDP/public-SSH firewall findings; unsupported
or inconclusive cases remain visible as not seen or deletion not verified.
Other providers still receive persistent tracking and ordinary PASS-based resolution.

Authorized reviewers (Manage Triage plus Manage Triage Exceptions) can use
**Confirm resource removal** for missing findings on **every provider**, including
AWS, Azure, GCP, and other supported providers. This requires explicit confirmation
and evidence, records who confirmed it, and is labeled **Removal confirmed by
reviewer**, not automatic cloud verification. A newer scan or changed finding
requires refreshing before confirmation. Normal users retain history visibility;
they cannot use this exception action. No historical FAIL is converted into PASS.

## 🚀 Production deployment

### Docker deployment

#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```

#### Build the Docker image

```bash
docker build -t prowler-cloud/ui . --target prod
```

#### Run the Docker container

```bash
docker run -p 3000:3000 prowler-cloud/ui
```

### Local deployment

#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```

#### Build the project

```bash
pnpm run build
```

#### Run the production server

```bash
pnpm start
```

## 🧪 Development deployment

### Docker deployment

#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```

#### Build the Docker image

```bash
docker build -t prowler-cloud/ui . --target dev
```

#### Run the Docker container

```bash
docker run -p 3000:3000 prowler-cloud/ui
```

### Local deployment

#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```

#### Install dependencies

```bash
pnpm install
```

**Note:** The `pnpm install` command will automatically configure prek Git hooks for code quality checks. If hooks are not installed, run from the repo root:

```bash
prek install
```

#### Run the development server

```bash
pnpm run dev
```

## Lighthouse / Vrika AI tool compatibility

The AI supports both `prowler_app_*` and `prowler_*` App tool names from MCP
releases. It presents canonical `prowler_app_*` names to the model, resolves
them to the server's original wire names, and forwards the current request's
authentication for both variants. Only explicitly allowlisted read-only tools
are eligible for aliases; write tools remain blocked.

Each question permits eight tool rounds, followed by a tools-disabled final
answer using the evidence already retrieved. Incomplete results must be
identified as such. A model that still requests tools is stopped with an
actionable error instead of reaching LangGraph's default 25-step recursion
limit. The budget resets for each new user question.

## Vrika branding

Visible product copy, onboarding, logos and favicon use Vrika branding.
Markdown presentation replaces legacy product names in prose, but preserves
commands, code blocks and actual link destinations. Compliance and graph labels
are branded only for display; stored framework names, resource identities,
MCP names, API paths and filter keys retain their original values.

## Technologies Used

- [Next.js 16](https://nextjs.org/docs/getting-started)
- [shadcn/ui](https://ui.shadcn.com/) (built on [Radix UI](https://www.radix-ui.com/))
- [Tailwind CSS 4](https://tailwindcss.com/)
- [TypeScript](https://www.typescriptlang.org/)
- [Framer Motion](https://www.framer.com/motion/)
- [next-themes](https://github.com/pacocoursey/next-themes)

## Git Hooks

The UI uses [prek](https://github.com/j178/prek) for pre-commit checks, configured in [`.pre-commit-config.yaml`](.pre-commit-config.yaml). `pnpm install` runs the postinstall script that installs hooks automatically. To re-install manually:

```bash
prek install --overwrite
```

On each commit, prek runs Prettier and ESLint against the staged files, plus a project-wide TypeScript check and the unit tests related to the staged changes. The full Next.js build runs in CI, not on commit.
