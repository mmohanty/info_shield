from __future__ import annotations
from dataclasses import dataclass
from typing import List, Protocol, Optional, Dict, Any

@dataclass
class PreprocessResult:
    text: str
    # map[i] = original_index of processed_text[i]
    index_map: List[int]

class Preprocessor(Protocol):
    """Transform text before scanning, *preserving an index mapping* back to original."""
    name: str
    def apply(self,
              text: str,
              index_map: List[int],
              *,
              context: Optional[Dict[str, Any]] = None
              ) -> PreprocessResult: ...
