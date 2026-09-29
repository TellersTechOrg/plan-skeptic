# plan-skeptic

Flag the parts of a Terraform/OpenTofu plan that need a human.

AI assistants write infrastructure changes that are fluent, plausible and
occasionally destructive: a rename that replaces a database, a policy widened
to `s3:*` to make an error go away, SSH opened "temporarily". The diff reads
fine. The plan says what will actually happen. `plan-skeptic` reads the plan
and points at the lines a reviewer must not skim.

It is not a policy engine and does not try to replace one. It is ten
opinionated checks about **what a change introduces**, tuned so that the output
is short enough to be read on every pull request.

```console
$ terraform plan -out=plan.out && terraform show -json plan.out > plan.json
$ plan-skeptic plan.json
plan-skeptic: 2 finding(s) across 1 resource change(s)

[HIGH  ] PS001 stateful-resource-replaced
         aws_db_instance.orders: aws_db_instance will be replaced because identifier changed: destroyed, then recreated empty.
         why a human should look: Replacement is destroy-then-create unless create_before_destroy is set. ...

[MEDIUM] PS010 recovery-guard-removed
         aws_db_instance.orders: deletion_protection changes true -> false.
```

Works the same with `tofu show -json`. No dependencies; Python 3.9+.

## Install

```sh
pipx install git+https://github.com/TellersTechOrg/plan-skeptic
# or run from a checkout
PYTHONPATH=src python3 -m plan_skeptic plan.json
```

## GitHub Action

```yaml
- run: |
    terraform plan -out=plan.out
    terraform show -json plan.out > plan.json
- uses: TellersTechOrg/plan-skeptic@v0.1.0
  with:
    plan-json: plan.json
    fail-on: high          # high | medium | low | never
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: plan-skeptic.sarif
```

Findings appear in the Security tab and inline on the pull request. Uploading
SARIF needs `security-events: write`.

## Rules

| Id | Severity | Flags |
|---|---|---|
| <a id="ps001"></a>PS001 | high | A data-holding resource (database, bucket, table, volume, key, PVC) is destroyed or replaced, and why it is being replaced |
| <a id="ps002"></a>PS002 | medium | Any other resource is deleted |
| <a id="ps003"></a>PS003 | high | An IAM policy newly grants `*` / `service:*`, or uses `NotAction` in an Allow |
| <a id="ps004"></a>PS004 | high | AdministratorAccess, PowerUserAccess or IAMFullAccess is attached |
| <a id="ps005"></a>PS005 | high | A trust policy lets any principal assume the role without a Condition |
| <a id="ps006"></a>PS006 | high | Ingress opened to 0.0.0.0/0 or ::/0 (medium for ports 80 and 443) |
| <a id="ps007"></a>PS007 | high | An S3 bucket made public by ACL, bucket policy or public access block |
| <a id="ps008"></a>PS008 | high | A database given `publicly_accessible = true` |
| <a id="ps009"></a>PS009 | medium | Encryption at rest set to false |
| <a id="ps010"></a>PS010 | medium | `deletion_protection` switched off, or `skip_final_snapshot` / `force_destroy` switched on |

A delete paired with a create of the same type and name gets a hint to use a
`moved` block, since that is what an unfinished refactor looks like.

### What it deliberately does not do

- **It reports changes, not state.** An update that leaves an existing
  0.0.0.0/0 rule alone is not flagged. Scanning everything on every plan is
  how a tool's output stops being read.
- **Unknown-after-apply values never trigger a rule.** Guessing at a value the
  plan itself cannot see would invent findings.
- **AWS first.** Replacement detection covers AWS, GCP, Azure and Kubernetes
  storage; the exposure and IAM rules are AWS-only in v0.1.

## Options

```
plan-skeptic PLAN [--format text|json|sarif] [--output FILE]
                  [--fail-on high|medium|low|never] [--disable RULE ...]
                  [--list-rules]
```

Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or above it,
`2` the input could not be reviewed. A binary plan file or a state file is
refused with exit 2 rather than reported clean.

## Fixtures

[`fixtures/`](fixtures/) holds seven flawed plans, each paired with the request
that produced it, plus a clean control. They are the exercises for the
[Confidently Wrong workshop](https://www.tellerstech.com/workshops/ai-era-infrastructure-risk-workshop/)
and come from the same material as the book
[*Confidently Wrong*](https://www.tellerstech.com/book/).

## Development

```sh
python3 -m unittest discover -s tests
```

## License

MIT
