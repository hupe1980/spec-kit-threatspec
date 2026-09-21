"""Fixture touchpoint for mitigation.context-isolation."""


def build_prompt(system: str, context: list[str], question: str) -> str:
    wrapped = "\n".join(f"<document untrusted=\"true\">{c}</document>" for c in context)
    return f"{system}\n\n{wrapped}\n\nUser: {question}"
