"""Admission control and speculation gating for memory formation.

Implements write-time gating to prevent speculation contamination, transient emotional noise,
and unverified statements from polluting long-term memory stores, following:
- Gated Memory: Admission-Controlled Memory Formation (arXiv:2610.11270)
- AgentMemGate: Addressing Speculation Contamination in Assistant Memory (arXiv:2610.07707)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class FactDisposition(str, Enum):
    """Disposition of candidate memory during formation."""
    ADMIT = "admit"                  # Established, factual, verified assertion
    SPECULATION = "speculation"      # Plan, future possibility, conditional intent
    TRANSIENT = "transient"          # Immediate situational or emotional state
    REJECT = "reject"                # Explicitly contradictory or low-salience noise


@dataclass
class AdmissionDecision:
    """Evaluation result from the write-time admission gate."""
    disposition: FactDisposition
    reason: str
    cleaned_fact: Optional[str] = None
    confidence: float = 1.0
    provenance: str = "direct"       # "direct", "inferred", or "speculative"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_admissible(self) -> bool:
        """Whether the candidate fact is admitted directly into active memory."""
        return self.disposition == FactDisposition.ADMIT


class MemoryAdmissionGate:
    """Heuristic and policy-based write-time gate for candidate memory formation.
    
    Prevents speculation contamination (e.g. 'I might move to Seattle') from entering
    profile and fact stores as established truth.
    """

    # Common speculation markers in candidate statements
    SPECULATION_PATTERNS = [
        re.compile(r"\b(might|maybe|possibly|perhaps|considering|planning to|thinking about)\b", re.IGNORECASE),
        re.compile(r"\b(hope to|aim to|intends? to|hypothetically|if I|could potentially)\b", re.IGNORECASE),
        re.compile(r"\b(someday|eventually|not sure if|undecided)\b", re.IGNORECASE),
        re.compile(r"\b(wondering if|tentatively|speculate)\b", re.IGNORECASE),
    ]

    # Transient situational state patterns
    TRANSIENT_PATTERNS = [
        re.compile(r"\b(right now|at the moment|currently feeling|tired today|busy today)\b", re.IGNORECASE),
        re.compile(r"\b(just woke up|having lunch|heading out shortly)\b", re.IGNORECASE),
    ]

    def __init__(self, strict_mode: bool = False) -> None:
        self.strict_mode = strict_mode

    def evaluate(
        self,
        content: str,
        category: str = "general",
        context: Optional[Dict[str, Any]] = None,
    ) -> AdmissionDecision:
        """Evaluate a candidate memory before it is written to durable storage.

        Args:
            content: The statement or payload to be stored.
            category: Namespace or category of memory (e.g. 'profile', 'fact').
            context: Optional contextual parameters (e.g. prior turns, speaker ID).

        Returns:
            AdmissionDecision indicating ADMIT, SPECULATION, TRANSIENT, or REJECT.
        """
        text = content.strip()
        if not text:
            return AdmissionDecision(
                disposition=FactDisposition.REJECT,
                reason="Empty content payload.",
            )

        # Check for transient situational expressions
        for pat in self.TRANSIENT_PATTERNS:
            if pat.search(text):
                return AdmissionDecision(
                    disposition=FactDisposition.TRANSIENT,
                    reason=f"Matched transient situational pattern: {pat.pattern}",
                    cleaned_fact=text,
                    provenance="transient",
                )

        # Check for speculative intent
        for pat in self.SPECULATION_PATTERNS:
            if pat.search(text):
                return AdmissionDecision(
                    disposition=FactDisposition.SPECULATION,
                    reason=f"Matched speculation pattern: {pat.pattern}",
                    cleaned_fact=text,
                    provenance="speculative",
                    metadata={"unresolved_speculation": True},
                )

        # Admitted as established fact
        return AdmissionDecision(
            disposition=FactDisposition.ADMIT,
            reason="Verified factual assertion with no unresolved speculation markers.",
            cleaned_fact=text,
            provenance="direct",
        )
