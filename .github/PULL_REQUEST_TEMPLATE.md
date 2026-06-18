## Summary
<!-- What does this PR do? What problem does it solve? -->


## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Refactor
- [ ] Test / coverage
- [ ] Documentation
- [ ] Configuration / infrastructure

## Clinical / HIPAA Impact
<!-- Does this PR touch any of the following? Check all that apply. -->
- [ ] PHI data models or storage
- [ ] Patient-facing API endpoints
- [ ] Authentication or authorization
- [ ] Audit logging
- [ ] FHIR / HL7 / EDI integrations
- [ ] Prior authorization or eligibility logic
- [ ] Consent workflows

If any box above is checked, a clinical reviewer must approve before merge.

---

## AI Tool Usage Declaration
<!-- REQUIRED — governance framework reads this section automatically -->

**Which AI tools were used to write or modify code in this PR?**
- [ ] No AI tools used
- [ ] Claude Code
- [ ] GitHub Copilot
- [ ] Cursor
- [ ] Windsurf
- [ ] ChatGPT
- [ ] Gemini
- [ ] Other: ___________

**Estimated % AI-generated:** ______%
<!-- Enter 0 if no AI was used, otherwise estimate the proportion of AI-written lines -->

**AI-generated sections reviewed by developer:** Yes / No
<!-- Did you read and understand each AI-generated block before including it? -->

**Summary of AI assistance:**
<!-- Briefly describe what you asked the AI to do, e.g.:
     "Used Claude to generate the enrollment form validators and reactive form setup.
      Manually reviewed all validation logic against the business rules doc." -->


---

## Self-Review Checklist
- [ ] No real PHI used in any test data, fixture, or code comment
- [ ] No hardcoded credentials, API keys, or connection strings
- [ ] All AI-generated code read and understood before submission
- [ ] New API endpoints have auth checks and audit log calls
- [ ] SQL / query strings use parameterized form — no string concatenation
- [ ] Error messages do not expose PHI values
