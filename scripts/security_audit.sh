#!/usr/bin/env bash
# Fail if the tree looks like an operator dump or live secret material.
# Needles are GENERIC only. Never put real homes, hostnames, mesh names,
# company internal labels, or tailnets here — those strings become the leak.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# Patterns that mean "this should not be in a public tree"
# Keep this list free of any specific operator identity.
# auth.raw template lines use "{safe_pw}" — only flag long non-placeholder values.
needles=$(
  cat <<'EOF' | paste -sd'|' -
BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY
sk_live_[A-Za-z0-9]{10,}
gho_[A-Za-z0-9]{20,}
ghp_[A-Za-z0-9]{20,}
github_pat_[A-Za-z0-9_]{20,}
xox[baprs]-[A-Za-z0-9-]{10,}
PROTON_AGENT_TOKEN=[A-Za-z0-9._\-]{16,}
auth\.raw\s*=\s*"[^{"][^"]{16,}"
[0-9a-z-]+\.ts\.net
100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]+\.[0-9]+
EOF
)

hits="$(git grep -nIE "$needles" -- ':!.git' ':!scripts/security_audit.sh' || true)"
if [ -n "$hits" ]; then
  echo "FAIL: secret or mesh-looking pattern in tree"
  # Do not echo the matching lines (may contain the secret).
  echo "$hits" | wc -l | awk '{print "hit_lines="$1}'
  exit 1
fi

# Absolute home paths in tracked files (except this script).
# Generic: any /home/<name>/ — operators should use $HOME in docs.
home_hits="$(git grep -nIE '/home/[A-Za-z0-9._-]+/' -- ':!.git' ':!scripts/security_audit.sh' || true)"
if [ -n "$home_hits" ]; then
  echo "FAIL: absolute /home/... path in tree — use \$HOME"
  echo "$home_hits" | wc -l | awk '{print "hit_lines="$1}'
  exit 1
fi

if find . -name '.env' -o -name '*.token' | grep -vE '^\./\.git|^\./\.venv' | grep -q .; then
  echo "FAIL: env/token filename present in worktree"
  exit 1
fi

echo "OK"
