# CapabilityFabric account-inventory plans

Polymorph can prepare a local, no-write metadata plan for CapabilityFabric:

```powershell
polymorph fabric inventory-plan "C:\Imports\accounts.xlsx" `
  --output "C:\Imports\accounts.fabric-plan.json"
```

The source may be CSV, JSON/JSON5 or XLSX. Automatic mapping recognizes common English and German headings for login origin, label, username, password-policy preference, risk tier and mutation approval. Unusual headings require explicit reviewed mappings:

```powershell
polymorph fabric inventory-plan "C:\Imports\accounts.csv" `
  --map origin=portal_location `
  --map username=login_handle `
  --output "C:\Imports\accounts.fabric-plan.json"
```

This path deliberately handles metadata only. A source with password-, token-, secret-, credential- or private-key-like columns is rejected. Excel formulas and formula-like mapped values are rejected rather than trusting cached or executable-looking content. The complete bounded record set is validated; ambiguous mappings and duplicate origin/username pairs fail closed.

The output is canonical JSON using `fabric.account-inventory-plan.v1`. It includes the exact source SHA-256, size, inspected schema fingerprint, mapping evidence and normalized entries. Its `plan_digest` covers the complete body. The machine-readable contract ships as `polymorph/data/fabric.account-inventory-plan.v1.schema.json`.

Polymorph does not enroll accounts, read passwords or receive CapabilityFabric authority. The operator previews and confirms the exact digest in CapabilityFabric, which independently revalidates the plan and source before requesting credentials through its hidden local input. Username values can be personal data even though they are not authentication secrets, so protect the artifact accordingly.
