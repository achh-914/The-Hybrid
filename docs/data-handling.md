# Data handling

*Last updated: 2026-11-19. Status: draft for design partners.*

This document explains what THE HYBRID stores, what it sends to third parties, and what it never does. It describes the **current implementation**. Anything not built yet is marked **Planned**. Items marked **[TO CONFIRM]** must be checked before this document is shared with a customer.

## Summary

| Question | Answer |
|---|---|
| Is the full contract text stored? | No. Only the extracted obligations are stored: clause number, page, a supporting excerpt and the structured requirement. |
| Is contract text sent to an LLM? | Yes, to Google's Gemini API, for extraction only. |
| Is AWS data sent to an LLM? | No. |
| Can THE HYBRID read your S3 objects? | No. The role has no permission to read object data. |
| Can THE HYBRID change your AWS account? | No. Access is read-only. |
| Who can see a tenant's data? | Only API keys that belong to that tenant, limited by role. Every route requires a key. |

## What we store

| Data | Content | Notes |
|---|---|---|
| Tenants and users | Tenant name, user ids, role, key revocation time | API keys are stored only as SHA-256 hashes and shown once |
| Requirement proposals and approved requirements | Obligations extracted from contracts (clause number, page, excerpt, structured fields) | Nothing becomes an active requirement without human approval |
| Audit trail | Who approved or rejected what, and when | Append-only |
| AWS snapshots | IAM authorization details (users, roles, groups, policies) and S3 configuration metadata (bucket policy, ACL, public access block, encryption) | Contains account ID and ARNs. No object data |
| Scans and reports | Findings, evidence and generated reports | |

All data is scoped by tenant. A tenant cannot read, list or modify another tenant's data.

## What we send to the LLM

- **Sent:** the contract text submitted for extraction (maximum 200,000 characters per request), plus our extraction instructions.
- **Not sent:** AWS snapshots, IAM data, API keys, scan results.
- **Provider:** Google Gemini API.
- **Output handling:** the model's output is validated and must be grounded in the contract text. Ungrounded or invalid output is rejected. The model does not decide findings: rules and graph analysis do.

**Provider data terms [TO CONFIRM]:** production use must run on the **paid tier** of the Gemini API (billing enabled on the Google Cloud project). Under Google's terms for paid services, prompts and responses are not used to improve Google's products and are processed under Google's data processing terms. Free-tier usage is not acceptable for customer contracts. Check the current Gemini API Additional Terms before sharing this document.

**Planned:** redaction of personal data before sending, and a choice of provider or region for customers who need it.

## What we read from AWS

| | |
|---|---|
| **Can read** | IAM account authorization details; S3 bucket list, bucket policy, bucket ACL, public access block and encryption configuration |
| **Cannot do** | Read object data, list objects, or create, modify or delete anything |
| **Trust** | Cross-account role protected by a unique External ID derived by the server for each tenant |
| **Session** | Short-lived, 1 hour maximum |
| **Revocation** | Delete the CloudFormation stack: access stops immediately |

We never ask for AWS access keys. We only receive the role ARN, which the server validates before use.

## What we do not do

- We do not read the contents of your S3 buckets.
- We do not change your infrastructure.
- We do not use your data to train or fine-tune models.
- We do not sell or share your data for advertising.

## Security controls in place

- Per-tenant isolation in data and API.
- Role-based access (`admin`, `reviewer`, `viewer`). Identity and role come from the API key, never from the request body.
- API keys stored hashed, shown once, revocable. Every route requires a key, enforced by an automated test.
- Append-only audit trail of approvals and rejections.
- Hardened extraction: prompt-injection test cases, fail-closed validation, grounding in the contract text.
- Server-derived External ID and role ARN validation for AWS access.

## Retention and deletion

- **Today:** data is kept until deletion is requested. Deletion is done by the operator on written request **[TO CONFIRM: response time]**.
- **Planned:** self-service deletion of a tenant's data, a documented backup and retention policy.
- **AWS access:** you can revoke it yourself at any time by deleting the CloudFormation stack.

## Hosting and subprocessors

| Service | Purpose | Data involved |
|---|---|---|
| Google (Gemini API) | Contract extraction | Contract text |
| Hosting provider **[TO FILL]** | Runs the application and database | All stored data |

**Encryption at rest:** the database is currently a SQLite file, so encryption at rest depends on the host disk. **Planned:** PostgreSQL with encryption and backups.

## Your responsibilities

- Only submit documents you are allowed to share with a service provider.
- Review and approve extracted requirements before they are used in scans.
- Keep API keys secret and revoke those no longer needed.
- THE HYBRID is decision support for security, compliance and legal teams. It does not provide legal advice or legal conclusions.

## Contact

Security reports: see [SECURITY.md](../SECURITY.md). Data questions: **[TO FILL: contact email]**.
