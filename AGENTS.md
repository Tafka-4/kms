# Repository Guidelines

## Project Structure & Module Organization
- Source: `index.ts` is the entry point. Add new modules under `src/` (e.g., `src/kms/`, `src/crypto/`, `src/storage/`) and re-export from `index.ts`.
- Build output: emit compiled JavaScript and type declarations to `build/`. Do not commit build artifacts.
- Config: `package.json`, `tsconfig.json`. Docs: `README.md`, `AGENTS.md`.

## Build, Test, and Development Commands
- Install: `npm install` (add dev deps: `npm i -D typescript @types/node`).
- Build: `npx tsc -p tsconfig.json --outDir build` (emits JS + `.d.ts`).
- Dev (optional): `npx tsx watch index.ts` for live execution, or use your editor’s TS/Node runner.
- Run built: `node build/index.js`.

## Coding Style & Naming Conventions
- TypeScript strict mode; ESM modules (`"type": "module"`).
- Indentation: 2 spaces; semicolons required; single quotes.
- Files: kebab-case `.ts`. Prefer named exports; avoid default exports.
- Names: classes `PascalCase`, functions/vars `camelCase`, constants `SCREAMING_SNAKE_CASE`.

## Testing Guidelines
- Framework: Vitest or Node’s built-in `node:test` (preferred: Vitest for TS ergonomics).
- Location: `src/**/__tests__/*.test.ts` or `tests/*.test.ts`.
- Naming: `*.test.ts`. Cover critical crypto/KMS paths and error cases.
- Run: `npx vitest` (CI: `npx vitest run --coverage`). Target >90% for core modules.

## Commit & Pull Request Guidelines
- Conventional Commits: `feat(kms): add key rotation`, `fix(crypto): correct IV length`, `chore(build): update tsconfig`.
- PRs: clear description, linked issues, tests updated/added, security notes when relevant, and before/after snippets for behavior changes.

## Security & Configuration Tips
- Never commit secrets/keys; use `.env` (already ignored) or system keychain/secret manager.
- Validate inputs and algorithm params; prefer constant-time operations where applicable.
- Run `npx tsc --noEmit` in CI to type-check and fail fast on typing regressions.

