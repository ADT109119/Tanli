# Security

探驪 Tanli(自主紅隊測試 Agent)is a security-testing tool. This file covers both the security of the tool itself and the responsible-use requirements.

## ⚠️ Responsible Use (Legal)

- Only test systems you have **explicit written authorization** to test.
- Unauthorized scanning/attacking is **illegal** in most jurisdictions.
- Default scope is **localhost-only** (`127.0.0.1`, `localhost`, `example.com`).
- Accessing internal/external targets requires a **signed authorization credential** (JWS). See below.

## Authorization Model

The tool enforces a signed-credential model (spec §5.1):

1. **Signer** issues a JWS (Ed25519) credential containing the Scope Statement + expiry.
2. **Agent** holds the signer's public key and verifies every credential.
3. **ScopeGuard** programmatically checks **every request** against the declared scope
   (IP/CIDR, port, path, method, time window). Requests outside scope are blocked.
4. **CRL** (`revoked.jws`) supports credential revocation / key rotation.

### Generating a credential

```bash
# 1. Write a scope statement (scope.yaml)
cat > scope.yaml <<'EOF'
authorized_by: "Your Org"
targets:
  - host: "10.0.0.5"
    cidr: "10.0.0.0/24"
    ports: [80, 443]
    paths: ["/api", "/login"]
    methods: ["GET", "POST"]
    window: "2026-08-13T00:00:00Z/2026-08-14T00:00:00Z"
    contact: "ops@example.com"
EOF

# 2. Signer creates an Ed25519 keypair
openssl genpkey -algorithm Ed25519 -out signer_private.pem
openssl pkey -in signer_private.pem -pubout -out signer_public.pem

# 3. Issue the credential
redteam gen-cred scope.yaml --key signer_private.pem -o credential.jws

# 4. Run with the credential
redteam run http://10.0.0.5 --auth-cred credential.jws
```

## Reporting Vulnerabilities

If you find a security issue in RedTeam Agent itself:

- **Do not** open a public issue.
- Email the maintainers, or open a private security advisory.
- Include: affected version, description, PoC, suggested fix.
- We aim to acknowledge within 48h and triage within 7 days.

## Threat Model (agent self-defense)

The agent tests prompt-injection targets. To avoid being itself compromised
(confused-deputy, spec §2.4):

- Target responses are treated as **data only**, never as instructions.
- Tool calls require explicit Planner-generated plan nodes.
- ScopeGuard enforces network/command boundaries regardless of target response.
- Python runtime in sandbox is hardened (no subprocess re-fork, restricted imports).
