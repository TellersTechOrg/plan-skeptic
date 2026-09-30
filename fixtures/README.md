# Fixtures: plans an assistant would happily hand you

Each file under `flawed/` is `show -json` output of a plan that answers the
question it was asked and does something else as well. They double as the
exercises for the *Confidently Wrong* workshop: show the prompt and the diff,
ask the room what they would approve, then run `plan-skeptic` on the file.

`01` is real OpenTofu 1.12 output, generated from `01-quickstart-postgres.tf`
with `tofu plan -refresh=false -out=plan.out && tofu show -json plan.out`
(dummy credentials; a create-only plan makes no AWS calls). The others need
prior state to produce an update or replacement, so they are written by hand in
the same shape, trimmed to the attributes the rules read.

| File | What was asked | What the plan also does | Rules |
|---|---|---|---|
| `01-quickstart-postgres` | "Give me a Postgres database the app can reach" | Public endpoint, unencrypted, no final snapshot, port 5432 open to the internet, `s3:*` on the side | PS003 PS006 PS008 PS009 PS010 |
| `02-rename-replaces-database` | "Rename the database to match our naming convention" | `identifier` forces replacement, so the database is destroyed and recreated empty; deletion protection switched off so the apply succeeds | PS001 PS010 |
| `03-iam-wildcard-creep` | "The exporter gets AccessDenied on KMS, fix it" | `s3:*` and `kms:*` on `*`; a second policy gains `NotAction: iam:*`, which allows everything except IAM | PS003 |
| `04-open-ssh-for-debugging` | "I can't SSH in to debug, and the app can't reach Redis" | Port 22 and every port open to 0.0.0.0/0 (the pre-existing 443 rule is correctly not reported) | PS006 |
| `05-public-bucket-for-static-site` | "Serve these assets as a static site" | Public ACL, public bucket policy, and the public access block relaxed, where CloudFront with OAC needed none of it | PS007 |
| `06-admin-to-unblock-ci` | "CI fails with AccessDenied on deploy" | AdministratorAccess on the CI role, and a trust statement that lets any AWS account assume it | PS004 PS005 |
| `07-refactor-without-moved-block` | "Move the orders resources into a module" | Destroys the table and log group and creates new ones at the module address, because nobody wrote a `moved` block | PS001 PS002 |
| `08-kms-open-to-unblock-encrypt` | "The app gets AccessDeniedException on Decrypt, fix the key policy" | Adds a statement granting `kms:*` to Principal `*` with no Condition | PS011 |

`clean/01-tags-only` is the control: a tags-only change on resources that
already carry a wildcard policy and a public 443 rule. It must produce nothing,
because the tool reports what a plan *introduces*.
