"""Vanilla browser client snippet generator for Aegis challenges."""

from __future__ import annotations


def generate_client_sdk(*, endpoint: str = "/.well-known/aegis/challenge",
                        token_header: str = "X-Aegis-Integrity") -> str:
    """Return a dependency-free, CSP-friendly JS challenge client."""
    safe_endpoint = endpoint.replace("\\", "\\\\").replace("'", "\\'")
    safe_header = token_header.replace("\\", "\\\\").replace("'", "\\'")
    return f"""/* AegisSovereign browser SDK — Cristi Labs / Marouan Rabai */
(function () {{
  'use strict';
  const endpoint = '{safe_endpoint}';
  async function solveAegisPow(challenge) {{
    const enc = new TextEncoder();
    const bits = async (value) => {{
      const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(value)));
      let n = 0;
      for (const b of bytes) {{ if (!b) {{ n += 8; continue; }} n += Math.clz32(b) - 24; break; }}
      return n;
    }};
    for (let i = 0; ; i += 1) {{
      if (await bits(challenge.challenge + ':' + i) >= challenge.difficulty) return String(i);
    }}
  }}
  window.AegisSovereign = {{
    async integrity() {{
      const response = await fetch(endpoint, {{ credentials: 'same-origin' }});
      const challenge = await response.json();
      if (challenge.pow) challenge.solution = await solveAegisPow(challenge.pow);
      return challenge;
    }},
    attach(request, token) {{ request.headers.set('{safe_header}', token); return request; }}
  }};
}})();
"""


class ClientSDK:
    """Compatibility wrapper around :func:`generate_client_sdk`."""

    @staticmethod
    def snippet(endpoint: str = "/.well-known/aegis/challenge") -> str:
        return generate_client_sdk(endpoint=endpoint)
