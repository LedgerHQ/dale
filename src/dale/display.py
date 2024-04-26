from typing import Any

INDENT = "    "


def summary(summary: str):
    return f"{summary}"


def title(level: int, title: str):
    return f"{INDENT * level}{title}"


def item_str(level: int, name: str, field: Any):
    return f"{INDENT * level}{name}: {str(field)}"
