# Connect Proton Mail (agent → human)

Use this when the user is not already on Proton Bridge + Himalaya 1.2.

## What to tell them (plain)

You will install three local pieces. Mail stays on Proton. I (the agent) only get a token to a program on this computer. I never see your Proton password.

1. Proton Mail Bridge (official app)
2. Himalaya 1.2 or newer (CLI)
3. This package (`proton-agent-mail`)

## Order

### 1. Bridge
- Install from https://proton.me/mail/bridge
- Sign in **in the Bridge app**, not in chat
- Confirm IMAP `127.0.0.1:1143` and SMTP `127.0.0.1:1025`
- Copy the **Bridge** username + password from the Bridge UI into Himalaya yourself
- Do not paste those into the agent chat

Agent check: port 1143 and 1025 listening on loopback.

### 2. Himalaya 1.2+
- `himalaya --version` must show `v1.2.0` or higher
- If `v1.1`: stop. Tell them 1.1 hangs on Bridge AUTH. Install 1.2 from GitHub releases
- Config: IMAP/SMTP to 127.0.0.1, `encryption.type = "none"` on loopback
- `chmod 600` the config file
- Agent check: `timeout 20 himalaya envelope list -s 3` succeeds

### 3. One command after they can type `login`

```
proton-agent-mail setup
```

The agent installs Himalaya 1.2, starts Bridge if needed, then **waits**. You tell the user to run `protonmail-bridge -c` → `login` in another window. When Bridge accepts the login, setup writes Himalaya + token (mode 0600) and prints how to `serve`. It never prints passwords.

Agent check: `proton-agent-mail health` → ok + himalaya 1.2+.  
`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18765/inboxes` → **401**.

### 4. First mail
`proton-agent-mail list` — envelopes only.  
Read one non-sensitive id.  
Do not send until they ask.

## If they get stuck

| They see | You say |
|----------|---------|
| Bridge not running | Open Proton Bridge and wait until it says connected |
| himalaya 1.1 | Upgrade; this tool will refuse to start |
| 401 on list | Token env not loaded in that shell |
| CaUsedAsEndEntity | Set Himalaya encryption to none on loopback |
| Hang on list | Timeout 20s; check Bridge, then Himalaya version |

## Never ask in chat
Proton account password. Bridge password. `auth.raw`. Recovery codes.
