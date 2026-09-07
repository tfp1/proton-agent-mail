<p align="center">
  <strong>proton-agent-mail</strong><br>
  <a href="https://github.com/PabloTheThinker/proton-agent-mail">GitHub</a>
  ·
  <a href="skills/proton-agent-mail/SKILL.md">Agent skill</a>
  ·
  <a href="SECURITY.md">Security</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://github.com/pimalaya/himalaya"><img src="https://img.shields.io/badge/Himalaya-1.2%2B-required-success?style=for-the-badge" alt="Himalaya 1.2+"></a>
  <a href="https://proton.me/mail/bridge"><img src="https://img.shields.io/badge/Proton-Bridge-6D4AFF?style=for-the-badge" alt="Proton Bridge"></a>
  <a href="https://agentskills.io"><img src="https://img.shields.io/badge/Agent_skill-SKILL.md-111111?style=for-the-badge" alt="Agent skill"></a>
</p>

**A local AgentMail-shaped inbox API for Proton Mail.** The AI agent talks to `127.0.0.1` with a bearer token. Proton Mail Bridge keeps the mailbox password. The model never sees it.

The human types `login` in Bridge. The agent installs Himalaya, watches until that login is accepted, writes config, and serves the API.

It is not Proton. It is not a cloud inbox factory. It is not Gmail.

<table>
<tr><td><b>AgentMail-shaped REST</b></td><td><code>/inboxes/…/messages</code> — list, read, threads, send. Same verbs an agent already knows from hosted AgentMail.</td></tr>
<tr><td><b>Hard wall</b></td><td>Bearer token + HMAC compare. Loopback bind. Envelope-first list. Body is a second call. Logs redact secrets.</td></tr>
<tr><td><b>User only logs in</b></td><td><code>proton-agent-mail setup</code> installs Himalaya 1.2, starts Bridge if present, and waits. You run <code>login</code> in the Bridge CLI. Setup finishes when <code>info</code> has IMAP credentials.</td></tr>
<tr><td><b>Himalaya 1.2 required</b></td><td>1.1 hangs on Proton Bridge <code>AUTH PLAIN</code>. This package refuses to start on older binaries.</td></tr>
<tr><td><b>Skill included</b></td><td>Agents load <code>skills/proton-agent-mail/SKILL.md</code> and walk a human through connect — without asking for passwords in chat.</td></tr>
<tr><td><b>Stdlib only</b></td><td>No extra Python deps. MIT. Clone and run.</td></tr>
</table>

---

## Quick start

```bash
git clone https://github.com/PabloTheThinker/proton-agent-mail.git
cd proton-agent-mail
pip install -e .

# 1) Official Proton Mail Bridge installed (once)
#    https://proton.me/mail/bridge

# 2) Agent does the rest; you only log in
proton-agent-mail setup
# other terminal:
#   protonmail-bridge -c
#   login

export PROTON_AGENT_TOKEN_FILE="$HOME/.config/proton-agent-mail.token"
export PROTON_AGENT_FROM="You <you@your-domain>"
proton-agent-mail serve
proton-agent-mail health
proton-agent-mail list
```

`setup` writes Himalaya + the token file at mode `0600`. It never prints passwords. If Bridge is missing it exits `2` with the official download URL — no unofficial installer.

---

## Getting started

```bash
proton-agent-mail setup     # install Himalaya 1.2, wait for Bridge login
proton-agent-mail serve     # loopback API (default 127.0.0.1:18765)
proton-agent-mail health    # { ok, himalaya, inbox }
proton-agent-mail list      # envelopes only
proton-agent-mail read ID
proton-agent-mail send --to ADDR --subject '…' --body '…'
proton-agent-mail token     # mint a bearer; do not commit it
```

### Environment

| Variable | Meaning |
|----------|---------|
| `PROTON_AGENT_TOKEN` | Bearer (or use the file) |
| `PROTON_AGENT_TOKEN_FILE` | Token file, mode 0600 |
| `PROTON_AGENT_FROM` | `From:` on send |
| `PROTON_AGENT_INBOX` | Inbox id (`default`) |
| `PROTON_AGENT_PORT` | `18765` |
| `PROTON_AGENT_BIND` | `127.0.0.1` |
| `PROTON_AGENT_FOLDERS` | Folders this agent may read, comma-separated. Unset = all. First entry is the default folder. |
| `PROTON_AGENT_MAX_ATTACHMENT` | Largest attachment served, bytes (25 MiB) |
| `HIMALAYA_BIN` | Optional path |

Binding anything other than loopback requires `PROTON_AGENT_ALLOW_LAN=1`. Do not do that casually.

---

## How it works

```
human  --login only-->  Proton Mail Bridge
agent  --Bearer------>  proton-agent-mail   127.0.0.1:18765
                              |
                         Himalaya 1.2+
                              |
                    Proton Bridge :1143 / :1025
                              |
                         Proton Mail
```

### HTTP

| Method | Path | Auth |
|--------|------|------|
| GET | `/health` | no |
| GET | `/inboxes` | yes |
| GET | `/inboxes/{id}/messages` | yes |
| GET | `/inboxes/{id}/messages/{id}` | yes |
| GET | `/inboxes/{id}/messages/{id}/attachments` | yes |
| GET | `/inboxes/{id}/messages/{id}/attachments/{n}` | yes |
| GET | `/inboxes/{id}/threads` | yes |
| POST | `/inboxes/{id}/messages/send` | yes |

```json
{"to":"owner@example.com","subject":"Hello","text":"…"}
```

---

## Documentation

| Doc | What |
|-----|------|
| [skills/proton-agent-mail/SKILL.md](skills/proton-agent-mail/SKILL.md) | What agents load |
| [skills/proton-agent-mail/references/connect-and-guide.md](skills/proton-agent-mail/references/connect-and-guide.md) | How the agent guides the human |
| [SECURITY.md](SECURITY.md) | Threat model and operator checklist |
| [LICENSE](LICENSE) | MIT |

Compatible with the [agentskills.io](https://agentskills.io) skill layout.

---

## Why not the others

| | This | Hosted AgentMail | Raw Himalaya in the agent |
|--|------|------------------|---------------------------|
| Proton | Yes, via official Bridge | No | Yes |
| Model sees mailbox password | No | N/A | Often yes |
| REST the agent already knows | Yes | Yes | No |
| Leaves your machine | Only through Bridge | Cloud | Depends |

Himalaya **1.2+** is the IMAP/SMTP engine because **1.1** mishandles Bridge `AUTH PLAIN`. That is a hard fail, not a warning.

---

## Honesty

- Not a second Proton
- Not hosting other people’s mail
- Does not skip Bridge
- Does not print `auth.raw`
- Does not ask for the Proton password in chat

---

## Tests

```bash
python3 -m unittest discover -s tests -q
```

---

## Contributing

Issues and PRs welcome. Keep operator paths, tokens, and live mailbox dumps out of the tree. Read [SECURITY.md](SECURITY.md) before filing anything that might contain credentials.

---

## License

[MIT](LICENSE) — © 2026 Pablo Navarro and contributors
