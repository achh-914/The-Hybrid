# THE HYBRID: contract vs cloud report

Snapshot: `fixtures/scenario-02/iam_real.json`

Scope: identity policies and role chaining in the snapshot. Not evaluated: resource policies, SCPs, permission boundaries.

## Clause `contract-4.2`

- Protected resource: `bucket:customer-data`
- Allowed by contract: `role:DataOps`
- Result: 2 unauthorized access path(s)

### [HIGH] role:app-role

- Path: role:app-role -> role:admin-role -> s3:customer-data
- Why: can_assume: iam:PassRole + ec2:RunInstances; can_access: s3:*
- Evidence:
  - clause: `contract-4.2` (sha256 602377ca2f7e78c7)
  - graph_path: `role:app-role -> role:admin-role -> s3:customer-data` (sha256 dd4c401f8ac082bc)
- Suggested change: Remove iam:PassRole on role:admin-role from the policies of role:app-role, or restrict it to approved services.
- What-if: After this change, role:app-role has no path to s3:customer-data in the snapshot.
- Action: human approval required before any change.

### [HIGH] role:admin-role

- Path: role:admin-role -> s3:customer-data
- Why: can_access: s3:*
- Evidence:
  - clause: `contract-4.2` (sha256 602377ca2f7e78c7)
  - graph_path: `role:admin-role -> s3:customer-data` (sha256 dcc663d21efe6961)
- Suggested change: Remove the S3 permission (s3:*) on s3:customer-data from the policies of role:admin-role.
- What-if: After this change, role:admin-role has no path to s3:customer-data in the snapshot.
- Action: human approval required before any change.

**Total findings: 2**
