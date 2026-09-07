# Security

## Threat model

An AI agent process can be prompt-injected. It must not hold the Proton Bridge
password or see IMAP/SMTP secrets.

Proton Mail Bridge is the only hop that talks to Proton. This package talks to
Bridge on **loopback only**.

## Guarantees we aim for

1. Agent authenticates with a random bearer token only.
2. Bridge credentials live in Himalaya config (mode 0600), never in agent context.
3. Listener is loopback unless the operator opts into LAN.
4. List endpoints do not include message bodies.
5. Logs are redacted for tokens and passwords.
6. Himalaya < 1.2 is a hard fail.
7. Serve **refuses** if Bridge IMAP/SMTP is bound off loopback.
8. Serve **refuses** a world-readable Himalaya config or token file.
9. Serve **refuses** if Himalaya `backend.host` / SMTP host is not loopback.
10. The IMAP child does not inherit `PROTON_AGENT_TOKEN`.
11. Folder names and message ids are allowlisted (no shell injection).
12. **This fork is read-only.** No send route, no SMTP stanza in the generated
    Himalaya config, and no wrapper for `message delete` / `move` / `copy` /
    `flag add` — those are IMAP writes, so blocking SMTP would not have covered
    them. Serve **refuses** to start if the config declares a send backend.

## Bridge hop

```
agent --token--> 127.0.0.1:18765 --> Himalaya --> 127.0.0.1:1143 (IMAP) --> Bridge --> Proton
```

- Set Bridge IMAP/SMTP host to `127.0.0.1` (not `0.0.0.0`).
- Loopback `encryption.type = "none"` is Proton’s documented local pattern.
  TLS to Proton is inside Bridge. Do not point Himalaya at a remote host.
- This tool never prints `auth.raw`.

## Operator checklist

- `proton-agent-mail token` — do not commit it.
- `chmod 600` Himalaya config and token file.
- Do not expose 18765, 1143, or 1025 on a public interface.
- Rotate the token if the agent session is compromised.
- Keep Proton Bridge updated.

## Public repo

No operator hosts, no house paths, no live tokens. The audit script uses
**generic** secret/mesh patterns only — never real home directories or hostnames
(those strings would be the leak). Run:

```bash
bash scripts/security_audit.sh
```

## Reporting

Open a private security advisory. Do not file public issues with credentials.
