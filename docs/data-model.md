# Unified Data Model

One graph links what a contract promises to what the cloud really allows.
Every node and edge carries `tenant_id`. Nothing crosses tenants.

## Nodes

| Node | Source | Key fields |
|---|---|---|
| Tenant | HYBRID | id, name |
| Contract | VENDORA | id, tenant_id, counterparty, file_hash |
| Clause | VENDORA | id, contract_id, number (e.g. 4.2), text, page |
| Requirement | M1 | id, clause_id, data_class, resource_selector, allowed_principals, status |
| AwsAccount | AEGIS | id, tenant_id, account_id |
| Identity | AEGIS | arn, type (role/user), account_id |
| Policy | AEGIS | arn, document_hash |
| Resource | AEGIS | arn, type (s3_bucket), tags |
| AttackPath | AEGIS | id, identity_arn, resource_arn, hops[] |
| Finding | M4 | id, rule_id, severity, status |
| Evidence | M4 | id, kind (policy/graph_path/clause), ref, hash |
| Review | M5 | id, finding_id, reviewer, decision, timestamp |

## Edges

- Contract -HAS_CLAUSE-> Clause
- Clause -YIELDS-> Requirement
- Requirement -APPLIES_TO-> Resource (matched by `resource_selector`)
- AwsAccount -OWNS-> Identity | Resource
- Identity -HAS_POLICY-> Policy
- Policy -ALLOWS-> Resource
- Identity -CAN_REACH-> Resource (materialized from an AttackPath)
- Finding -VIOLATES-> Requirement
- Finding -ABOUT-> AttackPath
- Finding -SUPPORTED_BY-> Evidence
- Review -DECIDES-> Finding

## Rules

1. A Requirement is `extracted` by the LLM, but only checked once a human sets it to `approved`.
2. Severity comes from deterministic rules. The LLM only explains.
3. A Finding without at least one Evidence of kind `clause` and one of kind `policy` or `graph_path` is invalid.
4. Every Review is append-only (audit trail).
5. AWS access is read-only.

## Example (Clause 4.2)

Clause 4.2 "Only authorized roles may access customer data in S3"
-> Requirement(data_class=customer_data, selector=tag:data=customer, allowed=[role/DataOps])
-> Resource s3://customer-data
<- AttackPath: role/DevAdmin (s3:* via AdminPolicy)
-> Finding(rule=EXCESS_ACCESS, severity=high), Evidence(clause 4.2 + policy + path)
-> Review(pending)
