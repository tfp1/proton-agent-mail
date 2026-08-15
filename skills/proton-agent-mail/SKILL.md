---
name: proton-agent-mail
description: "Connect Proton Mail for agents; guide the user."
version: 0.2.0
author: Pablo Navarro (PabloTheThinker)
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [email, protonmail, proton-bridge, agentmail, security]
    related_skills: []
---

# Proton Agent Mail

**What this is:** a local AgentMail-shaped inbox API so an AI agent can list, read, and send **Proton Mail** without holding the mailbox password.

**What this is not:** Proton cloud, Gmail, or AgentMail.to hosting.

The agent uses a bearer token against `127.0.0.1`. Himalaya 1.2+ talks to Proton Bridge. Bridge talks to Proton. Load `references/connect-and-guide.md` when the human is not set up yet.

## When to Use

- User says Proton, Proton Mail, Bridge, or “give the agent my mail”
- You need AgentMail-style REST on a self-hosted Proton account
- You must not put IMAP/SMTP passwords in the model context

Do not use for Gmail, Outlook, or skipping Bridge.

## Talk to the human

1. Explain the three pieces (Bridge, Himalaya 1.2, this API) in one short paragraph.
2. They sign into Bridge **in the Bridge app**. They paste the Bridge password into Himalaya config **themselves**.
3. Never ask for Proton password, Bridge password, or `auth.raw` in chat.
4. Confirm each step with a check you can run (ports, version, health, 401).
5. First success is `list` (headers only). Do not send until they ask.

## Prerequisites

- Proton Bridge: IMAP `127.0.0.1:1143`, SMTP `127.0.0.1:1025`
- Himalaya **v1.2.0+** already configured (`encryption.type = "none"` on loopback)
- `PROTON_AGENT_TOKEN` or `PROTON_AGENT_TOKEN_FILE` (mode 0600)
- `PROTON_AGENT_FROM` set to their From address
- `proton-agent-mail serve` on `127.0.0.1:18765`

If any of that is missing → `references/connect-and-guide.md`.

## How to Run

Prefer `terminal`. Do not print the token.

```
proton-agent-mail health
proton-agent-mail list --limit 15
proton-agent-mail read <id>
proton-agent-mail send --to ADDR --subject '…' --body '…'
```

REST (Authorization: Bearer $token):

| Method | Path |
|--------|------|
| GET | `/health` (no auth) |
| GET | `/inboxes` |
| GET | `/inboxes/{id}/messages` |
| GET | `/inboxes/{id}/messages/{id}` |
| GET | `/inboxes/{id}/threads` |
| POST | `/inboxes/{id}/messages/send` |

Default inbox id: `default`. Send JSON: `{"to":"a@b.com","subject":"Hi","text":"…"}`.

## Procedure (autonomous)

1. Run `proton-agent-mail setup`. Agent installs Himalaya 1.2 if needed and starts Bridge.
2. Tell the user: in another terminal, `protonmail-bridge -c` then `login`. They type Proton email/password/2FA **there only**.
3. Setup **watches** until Bridge `info` shows IMAP credentials. Then it writes Himalaya config (0600), mints a token file, and prints NEXT serve. Secrets are not printed.
4. `proton-agent-mail serve` then `health` / `list`.

If Bridge is not installed: setup exits 2 with the official download URL. Do not invent an unofficial installer.

## Pitfalls

- Himalaya 1.1 hangs on Bridge AUTH. This package refuses to start. Tell the user to upgrade.
- Empty token: server exits on purpose.
- `0.0.0.0` bind needs `PROTON_AGENT_ALLOW_LAN=1`. Do not suggest that first.
- `list` has no bodies. That is the design.
- 401 on list usually means the token is not in that shell.

## Verification

- Health JSON shows himalaya 1.2+.
- Unauthenticated GET `/inboxes` returns 401.
- `list` returns ids/from/subject, not RFC822.
- `python3 -m unittest discover -s tests -q` passes.
