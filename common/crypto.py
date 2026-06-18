from __future__ import annotations
import hashlib
from typing import List


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_log(raw_log: str) -> str:
    return sha256(raw_log.encode("utf-8"))


def build_merkle_tree(leaves: List[str]) -> List[str]:
    if not leaves:
        return []

    current_level = leaves[:]
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            if i + 1 < len(current_level):
                right = current_level[i + 1]
            else:
                right = left
            combined = left + right
            next_level.append(sha256(combined.encode("utf-8")))
        current_level = next_level

    return current_level


def compute_micro_roots(buckets: List[List[str]]) -> List[str]:
    micro_roots: List[str] = []
    for bucket_logs in buckets:
        if not bucket_logs:
            continue
        leaves = [hash_log(log) for log in bucket_logs]
        tree_top = build_merkle_tree(leaves)
        if tree_top:
            micro_roots.append(tree_top[0])
    return micro_roots


def compute_super_root(micro_roots: List[str]) -> str:
    if not micro_roots:
        return sha256(b"null")
    tree_top = build_merkle_tree(micro_roots)
    return tree_top[0] if tree_top else sha256(b"null")
