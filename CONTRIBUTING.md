<p align="center">
<img src="https://github.com/achh-914/The-Hybrid/raw/main/docs/banner-contributing.svg" alt="Contributing" width="100%">
</p>

<p align="center">
  <a href="README.md">Home</a> ·
  <a href="SECURITY.md">Security</a> ·
  <b>Contributing</b> ·
  <a href="CODE_OF_CONDUCT.md">Code of Conduct</a> ·
  <a href="LICENSE">License</a>
</p>

---

> [!IMPORTANT]
> THE HYBRID is a **proprietary** project. The source code is not open source, and external contributions are **not accepted by default**.

## Ways to help

| I want to... | Do this |
|---|---|
| Report a bug or give feedback | Open an issue with clear steps to reproduce. Do not include real contracts, credentials or customer data. |
| Report a security issue | Do **not** open an issue. Follow [SECURITY.md](SECURITY.md). |
| Contribute code | Contact the owner first. Code is accepted by invitation only, after you agree in writing to the terms below. |

## Terms for invited contributions

- All contributions become the property of the copyright holder, or are licensed to them under terms agreed in writing before the work starts.
- You confirm that you wrote the code yourself, or have the right to submit it, and that it contains no code under a license that conflicts with proprietary use (for example GPL or AGPL).
- Do not commit secrets, customer data or real scan results.

## Development workflow

1. Create a branch from `main`: `feat/<short-name>`, `fix/<short-name>` or `docs/<short-name>`.
2. Keep changes focused: one concern per pull request.
3. Add or update tests. CI must be green before review.
4. Use clear commit messages: `feat:`, `fix:`, `test:`, `docs:`, `ci:`.
5. Open a pull request describing what changed and why.

## Project rules

| Rule | Meaning |
|---|---|
| **Rules decide, the LLM explains** | Compliance verdicts come from deterministic code, never from model output alone. |
| **Fail closed** | Invalid or ungrounded extraction output is rejected. |
| **Tenant isolation** | Every query and endpoint is scoped to the caller's tenant. New endpoints need an isolation test. |
| **Read-only AWS** | No code may modify customer infrastructure. |
| **Evidence for every finding** | No finding without the clause, policy or path behind it. |
| **Untrusted contracts** | Treat contract text as untrusted input and add injection test cases for any new extraction path. |

## Conduct

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

---

<p align="center"><a href="README.md">← Back to README</a></p>
