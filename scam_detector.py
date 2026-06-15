"""Heuristic scam/phishing message detector.

Analyzes a piece of text (SMS, email, chat message, etc.) and flags
common patterns associated with scams: urgency, requests for money or
personal info, suspicious links, prize/lottery claims, and impersonation
of banks, government agencies, or delivery services.
"""

import argparse
import re
from dataclasses import dataclass, field


@dataclass
class ScamAnalysis:
    score: int
    risk_level: str
    reasons: list = field(default_factory=list)


# Each rule: (label, weight, regex pattern, flags)
RULES = [
    ("urgency language", 2,
     r"\b(act now|urgent|immediately|right away|expire[sd]?|act fast|"
     r"final notice|last chance|within 24 hours)\b"),
    ("requests personal/financial info", 3,
     r"\b(social security|ssn|bank account|routing number|pin code|"
     r"credit card number|password|verify your identity|account details)\b"),
    ("requests payment via gift cards or crypto", 3,
     r"\b(gift card|itunes card|google play card|bitcoin|crypto|wire transfer|"
     r"western union|moneygram)\b"),
    ("prize or lottery claim", 3,
     r"\b(you('ve| have) won|congratulations.*(won|winner)|claim your prize|"
     r"lottery|sweepstakes|free gift)\b"),
    ("impersonation of bank/government/delivery", 2,
     r"\b(irs|internal revenue service|social security administration|"
     r"your bank|paypal|amazon support|apple support|fedex|ups|usps).{0,40}"
     r"(suspend|verify|locked|delivery failed|update (your )?account)\b"),
    ("threatening account suspension/legal action", 2,
     r"\b(account (has been |will be )?(suspended|locked|closed|terminated)|"
     r"legal action|arrest warrant|you will be (fined|charged))\b"),
    ("suspicious shortened or odd links", 2,
     r"(https?://)?(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|[a-z0-9-]+\.(xyz|top|club|info))"),
    ("asks to click a link to confirm/verify", 2,
     r"\b(click here|click the link below|tap (this|here)|follow this link).{0,40}"
     r"(verify|confirm|update|claim|unlock)?\b"),
]

_COMPILED_RULES = [
    (label, weight, re.compile(pattern, re.IGNORECASE))
    for label, weight, pattern in RULES
]


def analyze_text(text: str) -> ScamAnalysis:
    """Analyze text and return a ScamAnalysis with score and reasons."""
    score = 0
    reasons = []

    for label, weight, pattern in _COMPILED_RULES:
        if pattern.search(text):
            score += weight
            reasons.append(label)

    if score >= 6:
        risk_level = "high"
    elif score >= 3:
        risk_level = "medium"
    elif score > 0:
        risk_level = "low"
    else:
        risk_level = "none"

    return ScamAnalysis(score=score, risk_level=risk_level, reasons=reasons)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scam_detector",
        description="Analyze a message for common scam indicators.",
    )
    parser.add_argument(
        "text",
        nargs="?",
        help="The message text to analyze. If omitted, reads from stdin.",
    )
    return parser


def main(argv=None):
    import sys

    parser = _build_parser()
    args = parser.parse_args(argv)

    text = args.text if args.text is not None else sys.stdin.read()
    result = analyze_text(text)

    print(f"Risk level: {result.risk_level} (score: {result.score})")
    if result.reasons:
        print("Flagged for:")
        for reason in result.reasons:
            print(f"  - {reason}")
    else:
        print("No common scam indicators detected.")


if __name__ == "__main__":
    main()
