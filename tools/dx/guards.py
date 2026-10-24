"""Operational validation that remains active under Python optimisation."""


def require(condition, message="Evidence validation failed"):
    if not condition:
        raise ValueError(message)
