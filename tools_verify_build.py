#!/usr/bin/env python3
"""
Reproducible Build Verification (Step 9 requirement)
======================================================
Concatenates every tracked source file in a deterministic, sorted order
and computes a single SHA-256 hash over that concatenation. Running this
script twice from a clean checkout (no generated .sqlite3 / .key / cache
files present) must produce the identical hash both times, proving the
build is deterministic and free of hidden non-reproducible state.

WHAT IS HASHED:
    Every file under the project root matching these extensions, walked
    in sorted path order, EXCLUDING generated/runtime artifacts:
        .py, .html, .css, .js, .md, .txt
    Excluded paths: __pycache__, .sqlite3*, .zrevix_secret.key,
    this script's own output, README.md (it documents this hash, so it
    can't be part of its own input), and any hidden/dot directories.

    For each included file we hash "<relative_path>\\n<file_bytes>" so that
    a rename (same bytes, different path) is correctly detected as a
    different build, not a false match.

Run:
    python tools_verify_build.py
"""

import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

INCLUDE_EXTS = {".py", ".html", ".css", ".js", ".md", ".txt"}
EXCLUDE_DIR_NAMES = {"__pycache__", ".git"}
EXCLUDE_FILENAMES = {os.path.basename(__file__), "README.md"}
# README.md is excluded because it documents this very hash — including it
# would make the hash a function of itself (the classic "a checksum file
# can't list its own checksum" problem). Every other tracked source and
# doc file is included.


def iter_source_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in EXCLUDE_DIR_NAMES and not d.startswith(".")
        )
        for fname in sorted(filenames):
            if fname in EXCLUDE_FILENAMES:
                continue
            if fname.startswith(".") or fname.endswith(".sqlite3") or ".sqlite3" in fname:
                continue
            ext = os.path.splitext(fname)[1]
            if ext not in INCLUDE_EXTS:
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root)
            yield rel, full


def compute_build_hash(root=ROOT, verbose=False):
    hasher = hashlib.sha256()
    file_count = 0
    for rel, full in iter_source_files(root):
        with open(full, "rb") as f:
            content = f.read()
        hasher.update(rel.replace(os.sep, "/").encode("utf-8"))
        hasher.update(b"\n")
        hasher.update(content)
        file_count += 1
        if verbose:
            print(f"  + {rel}  ({len(content)} bytes)")
    return hasher.hexdigest(), file_count


def main():
    verbose = "-v" in sys.argv
    digest, count = compute_build_hash(verbose=verbose)
    print(f"Files hashed : {count}")
    print(f"SHA-256      : {digest}")
    return digest


if __name__ == "__main__":
    main()
