# ADR 0001: Scope and limits

Status: accepted

## What THE HYBRID checks today

- Identity policies and role chaining (AssumeRole, iam:PassRole) in an IAM
  snapshot, evaluated by AEGIS.
- Explicit Deny in identity policies.
- Contract obligations about who may access data in S3, extracted from the
  contract text and approved by a human.

## What it does not check yet

- S3 bucket policies and ACLs
- Service control policies (SCPs) and permission boundaries
- Session policies and condition keys
- Resources other than S3 buckets
- Anything outside the snapshot (live state, network paths)

A report that finds no unauthorized path means "none found in this snapshot
under these rules", not "compliant".

## Decisions

1. The LLM only proposes. A human binds each proposal to technical IDs and
   approves it. Unapproved requirements are never checked.
2. Severity comes from deterministic rules, never from the LLM.
3. A finding without clause evidence and technical evidence is invalid.
4. Every approval and rejection is appended to an audit log.
5. AWS access is read-only. No automatic changes.
6. THE HYBRID gives no legal conclusion. It helps security, compliance and
   legal teams find and verify risks.
