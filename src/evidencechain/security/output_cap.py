"""Output size capping to prevent context window overflow.

Large tool outputs (e.g., full MFT dumps) are truncated before being
returned to the LLM. The full output is always saved to disk with a hash
for audit purposes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..config import MAX_OUTPUT_SIZE


def cap_output(
    output: str,
    max_size: int = MAX_OUTPUT_SIZE,
    save_path: str | None = None,
) -> tuple[str, bool, str]:
    """Cap output to max_size bytes and optionally save the full output.

    Args:
        output: The raw output string.
        max_size: Maximum size in bytes to return.
        save_path: If provided, save the full output to this path.

    Returns:
        Tuple of (possibly_truncated_output, was_truncated, sha256_hash).
    """
    output_bytes = output.encode("utf-8", errors="replace")
    full_hash = hashlib.sha256(output_bytes).hexdigest()

    # Save full output to disk if path provided
    if save_path:
        path = Path(save_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")

    if len(output_bytes) <= max_size:
        return output, False, full_hash

    # Truncate to max_size, trying to break at a newline
    truncated_bytes = output_bytes[:max_size]
    truncated = truncated_bytes.decode("utf-8", errors="replace")

    # Try to break at the last newline within the limit
    last_newline = truncated.rfind("\n")
    if last_newline > max_size * 0.8:  # Only break if we keep >80% of content
        truncated = truncated[:last_newline]

    lines_total = output.count("\n") + 1
    lines_shown = truncated.count("\n") + 1

    truncated += (
        f"\n\n--- OUTPUT TRUNCATED ---\n"
        f"Showing {lines_shown} of {lines_total} lines "
        f"({len(truncated_bytes):,} of {len(output_bytes):,} bytes).\n"
        f"Full output saved to: {save_path or 'not saved'}\n"
        f"Full output SHA-256: {full_hash}\n"
    )

    return truncated, True, full_hash
