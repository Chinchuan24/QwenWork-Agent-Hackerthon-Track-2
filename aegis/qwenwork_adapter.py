"""Local callable bridge, not a live QwenWork session integration.

The main integrator creates the Aegis run/session and supplies its token.
Call adapter(tool, args, idem_key) or adapter.call(tool, args, idem_key).
Every action, including unknown tools, uses gateway.handle_call unchanged.
The caller supplies stable retry keys; this bridge never creates keys, approves
holds, executes tools itself, or changes the world. Live wiring awaits the main
integrator; the label does not attest to any external session or model use.
"""
from . import gateway


class QwenWorkAdapter:
    label = 'stand-in'
    live_status = 'waiting for key'

    def __init__(self, token: str):
        self._token = token

    def call(self, tool: str, args: dict, idem_key: str = None) -> dict:
        """Return the gateway decision, including its shielded result and proof IDs."""
        try:
            return gateway.handle_call(self._token, tool, args, idem_key)
        except Exception:
            # Do not expose exception text, which may contain private arguments.
            return {'verdict': 'block', 'action_id': None, 'mode': 'enforce',
                    'reasons': [{'rule': 'ADAPTER-ERROR',
                                 'reason': 'Local gateway call failed closed.'}]}

    __call__ = call
