"""Nạp bảng phân loại tên miền (6 nhóm) và tra cứu theo hậu tố dài nhất."""
from __future__ import annotations
import csv
from importlib import resources
from .domains import longest_suffix_lookup
from .policy import CATEGORIES


def load_classification(path: str | None = None) -> dict[str, str]:
    if path:
        f = open(path, newline="", encoding="utf-8")
    else:
        f = resources.files("ogk_common").joinpath("data/classification.csv").open("r", newline="", encoding="utf-8")
    with f:
        table = {}
        for row in csv.DictReader(f):
            if row["category"] in CATEGORIES:
                table[row["domain"].strip().lower()] = row["category"]
        return table


def category_of(host: str, table: dict[str, str]) -> str:
    _, cat = longest_suffix_lookup(host, table)
    return cat or "unclassified"
