# Mock EMR — Claude Code Project Instructions

## Project Context

This is a mock Electronic Medical Record (EMR) Angular application built for
demonstrating healthcare AI governance. It is subject to HIPAA regulations.
All code generated in this project must meet HIPAA technical safeguard requirements.

## Stack
- Angular 17 (module-based, TypeScript strict mode)
- RxJS 7 — use `Observable` patterns throughout, never `.subscribe()` in services
- Reactive Forms — all forms must use `FormBuilder` with typed validators
- SCSS — use CSS custom properties from `styles.scss`, no hardcoded colors

## Non-Negotiable Governance Rules

### PHI — What never goes in code
Never use real patient data in any source file, test, fixture, or comment.
Use synthetic identifiers: `SYNTHETIC-P-00001`, `000-00-0001` (SSN), `1900-01-01` (DOB).

### Security — Always enforce these
- No hardcoded credentials, API keys, or endpoints — use `environment.ts`.
- HTTPS only for all API calls in `environment.prod.ts`.
- All API calls go through `PatientService` or a dedicated feature service.
- No PHI in `console.log()` calls — log event type and `referenceId` only.
- Auth token lives in `sessionStorage` via `AuthInterceptor` — never in `localStorage`.

### Required patterns when generating PHI-touching code
1. Route the call through the appropriate service (`PatientService`, etc.)
2. Emit an `AuditLogService.log()` entry with `eventType`, `resourceType`, `resourceId`
3. `resourceId` must always be the surrogate `referenceId` — never a PHI value
4. Add reactive form validators for any new PHI input field

## Architecture

```
src/app/
├── core/
│   ├── models/          ← interfaces only — patient.model.ts, audit-log.model.ts
│   ├── services/        ← patient.service.ts, audit-log.service.ts
│   └── interceptors/    ← auth.interceptor.ts
└── features/
    └── enrollment/      ← enrollment-form, enrollment-list
        ├── enrollment.module.ts
        └── enrollment-routing.module.ts
```

## Code Style
- No inline comments explaining what the code does
- No `any` types — use proper interfaces from `core/models/`
- Template expressions must not call methods that return PHI — bind to component properties
- Error messages shown to users must never contain PHI values

## Governance Framework
This repo runs automated checks on every PR via `.github/workflows/governance.yml`.
The framework scans for PHI patterns, HIPAA SAST rules, and dependency CVEs.
If your generated code would trigger a finding, fix it before suggesting it.
