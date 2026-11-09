# Design decisions: Detection-as-Code Pipeline

### 1. Sigma as the rule format
- **Alternatives:** write SPL directly; vendor-specific formats.
- **Why:** vendor-neutral YAML, a large community rule base, and pySigma converts to many SIEMs, so switching SIEMs does not mean rewriting detections.

### 2. A small in-repo evaluator for unit tests
- **Alternatives:** test only by running queries in a live Splunk; use a heavier test framework.
- **Why:** tests run in under a second in CI with no SIEM. The evaluator supports exactly the Sigma features these rules use. pySigma conversion runs as a separate step, so both "logic is right" and "it converts" are checked.
- **Trade-off:** the evaluator could drift from real Sigma semantics; the conversion step and a live smoke test in Splunk cover that.

### 3. Every rule must ship with positive and negative samples
- **Why:** a rule without a false-positive test is how alert fatigue starts. The test fails if the sample file is missing.

### 4. ATT&CK tag required on every rule
- **Why:** coverage reporting depends on it; the metadata test enforces it.

### 5. Deploy via the Splunk REST API with a token, skipped when secrets are absent
- **Why:** no SDK dependency; token auth; forks and PRs never touch production because secrets are only in the protected `splunk` environment.

### 6. Fixing the access-key rule with `|exists: false` instead of a field comparison
- **Why:** Splunk's backend cannot negate field-to-field comparisons. CloudTrail omits `requestParameters.userName` when a user creates their own key, so the simpler rule is both portable and correct.

### 7. CloudTrail-focused rule set
- **Why:** it ties into the AWS projects and is a high-value log source; the same pipeline handles Windows, EDR or identity logs by adding logsource types.
