"""proton-agent-mail — AgentMail-shaped local API over Proton Bridge.

Security model
--------------
The *agent* authenticates with a bearer token.
The *service* holds Proton Bridge credentials (via Himalaya config).
The agent never sees the mailbox password.

Himalaya 1.2+ is required (1.1 hangs / mishandles Bridge AUTH PLAIN).
Bind 127.0.0.1 only unless explicitly overridden.
"""

from .security import MIN_HIMALAYA, require_himalaya_version

__version__ = "0.1.0"
__all__ = ["MIN_HIMALAYA", "require_himalaya_version", "__version__"]
