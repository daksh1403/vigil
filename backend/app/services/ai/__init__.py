"""AI services package.

Submodules are imported lazily to avoid forcing heavy optional dependencies
(httpx, sentence-transformers) on lightweight consumers (e.g. unit tests that
only need the FP classifier).
"""
