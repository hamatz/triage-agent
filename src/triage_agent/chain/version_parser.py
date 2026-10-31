"""Distro-specific package version comparison engine (dpkg & rpm rules) in pure Python.

Upholds 'Never present fabricated data as truth'. Strictly distinguishes package version
order from naive string comparison or upstream kernel release formats.
"""

import re
from typing import Any, List, Optional, Tuple


def _split_debian_part(s: str):
    """Split a Debian version string component into alternating non-digit and digit segments."""
    parts = []
    i = 0
    n = len(s)
    while i < n:
        # 1. Non-digit segment
        nd_chars = []
        while i < n and not s[i].isdigit():
            nd_chars.append(s[i])
            i += 1
        if nd_chars:
            parts.append(("str", "".join(nd_chars)))
        
        # 2. Digit segment
        d_chars = []
        while i < n and s[i].isdigit():
            d_chars.append(s[i])
            i += 1
        if d_chars:
            parts.append(("int", int("".join(d_chars))))
    return parts


def _order_deb_char(c: str) -> int:
    """Debian character ordering (Debian Policy Manual 5.6.12):
    - '~' sorts earlier than empty string (-1)
    - empty string sorts at 0
    - letters (a-z, A-Z) sort earlier than non-letters (symbols like '+', '.', etc.)
    """
    if c == "~":
        return -1
    if not c:
        return 0
    if c.isalpha():
        return 100 + ord(c)
    # Symbols / non-letters sort after letters
    return 1000 + ord(c)


def _compare_deb_strings(a: str, b: str) -> int:
    """Compare two non-digit strings according to Debian policy."""
    i = 0
    len_a, len_b = len(a), len(b)
    while i < len_a or i < len_b:
        ca = a[i] if i < len_a else ""
        cb = b[i] if i < len_b else ""
        if ca == cb:
            i += 1
            continue
        oa = _order_deb_char(ca)
        ob = _order_deb_char(cb)
        if oa != ob:
            return -1 if oa < ob else 1
        i += 1
    return 0


def compare_debian_parts(a: str, b: str) -> int:
    """Compare two Debian version subparts (upstream_version or debian_revision)."""
    segs_a = _split_debian_part(a)
    segs_b = _split_debian_part(b)
    
    max_len = max(len(segs_a), len(segs_b))
    for i in range(max_len):
        type_a, val_a = segs_a[i] if i < len(segs_a) else ("str", "")
        type_b, val_b = segs_b[i] if i < len(segs_b) else ("str", "")
        
        if type_a == "int" and type_b == "int":
            if val_a != val_b:
                return -1 if val_a < val_b else 1
        else:
            sa = str(val_a)
            sb = str(val_b)
            cmp_res = _compare_deb_strings(sa, sb)
            if cmp_res != 0:
                return cmp_res
    return 0


def parse_debian_version(v_str: str) -> Tuple[int, str, str]:
    """Parse a full Debian/Ubuntu version into (epoch, upstream_version, debian_revision)."""
    s = v_str.strip()
    epoch = 0
    if ":" in s:
        epoch_part, s = s.split(":", 1)
        try:
            epoch = int(epoch_part)
        except ValueError:
            pass
    
    if "-" in s:
        upstream, revision = s.rsplit("-", 1)
    else:
        upstream = s
        revision = "0"
    return epoch, upstream, revision


def compare_debian_versions(v1: str, v2: str) -> int:
    """Compare two Debian/Ubuntu package version strings.
    
    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    e1, u1, r1 = parse_debian_version(v1)
    e2, u2, r2 = parse_debian_version(v2)
    
    if e1 != e2:
        return -1 if e1 < e2 else 1
    
    cmp_u = compare_debian_parts(u1, u2)
    if cmp_u != 0:
        return cmp_u
    
    return compare_debian_parts(r1, r2)


def compare_rpm_versions(v1: str, v2: str) -> int:
    """Compare two RPM version strings according to rpmvercmp rules."""
    # Split into segments of contiguous digits, contiguous letters, or delimiters
    def _split_rpm(s: str) -> List[Tuple[str, Any]]:
        segments = []
        i = 0
        n = len(s)
        while i < n:
            c = s[i]
            if c.isalnum() or c in ("~", "^"):
                if c.isdigit():
                    num_chars = []
                    while i < n and s[i].isdigit():
                        num_chars.append(s[i])
                        i += 1
                    segments.append(("int", int("".join(num_chars))))
                elif c == "~":
                    segments.append(("tilde", "~"))
                    i += 1
                elif c == "^":
                    segments.append(("caret", "^"))
                    i += 1
                else:
                    alpha_chars = []
                    while i < n and s[i].isalpha():
                        alpha_chars.append(s[i])
                        i += 1
                    segments.append(("str", "".join(alpha_chars)))
            else:
                # Delimiter
                i += 1
        return segments

    segs1 = _split_rpm(v1)
    segs2 = _split_rpm(v2)
    max_len = max(len(segs1), len(segs2))

    for i in range(max_len):
        if i >= len(segs1):
            # segs1 is shorter
            t2, _ = segs2[i]
            if t2 == "tilde":
                return 1
            return -1
        if i >= len(segs2):
            # segs2 is shorter
            t1, _ = segs1[i]
            if t1 == "tilde":
                return -1
            return 1

        t1, val1 = segs1[i]
        t2, val2 = segs2[i]

        if t1 == "tilde" and t2 != "tilde":
            return -1
        if t2 == "tilde" and t1 != "tilde":
            return 1
        if t1 == "caret" and t2 != "caret":
            return -1
        if t2 == "caret" and t1 != "caret":
            return 1

        if t1 == "int" and t2 == "int":
            if val1 != val2:
                return -1 if val1 < val2 else 1
        elif t1 == "str" and t2 == "str":
            if val1 != val2:
                return -1 if val1 < val2 else 1
        else:
            # Different types: numbers are newer than letters in RPM
            return 1 if t1 == "int" else -1

    return 0


def is_kernel_package_vulnerable(
    distro: Optional[str],
    installed_version: Optional[str],
    fixed_version: Optional[str],
) -> Optional[bool]:
    """Determine whether the installed kernel package version is vulnerable against fixed_version.
    
    Args:
        distro: OS distribution identifier (e.g. 'ubuntu', 'debian', 'almalinux', 'rhel')
        installed_version: Package version string (e.g. '6.8.0-40.40')
        fixed_version: First patched version string (e.g. '6.8.0-47.47')
        
    Returns:
        True: Vulnerable (installed < fixed)
        False: Fixed / Safe (installed >= fixed)
        None: Indeterminate (version missing or unsupported format; caller must fail-safe to vulnerable!)
    """
    if not installed_version or not fixed_version:
        return None
    
    d_clean = (distro or "").strip().lower()
    
    try:
        if d_clean in ("ubuntu", "debian"):
            # Debian/Ubuntu dpkg version rules
            res = compare_debian_versions(installed_version, fixed_version)
            return res < 0
        elif d_clean in ("rhel", "almalinux", "rocky", "centos", "fedora"):
            # RPM style version compare
            res = compare_rpm_versions(installed_version, fixed_version)
            return res < 0
        else:
            # Unknown / unsupported distribution: NEVER guess or assume safe!
            return None
    except Exception:
        return None
