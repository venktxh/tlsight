"""JA3 / JA3S TLS fingerprints (https://github.com/salesforce/ja3).

JA3  = SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
JA3S = SSLVersion,Cipher,Extensions
Values are decimal, list items joined with '-', GREASE values removed, then MD5.
"""

import hashlib

from .ciphers import is_grease


def _join(values) -> str:
    return "-".join(str(v) for v in values if not is_grease(v))


def ja3_string(version, ciphers, extensions, groups, point_formats) -> str:
    return ",".join([str(version), _join(ciphers), _join(extensions),
                     _join(groups), _join(point_formats)])


def ja3s_string(version, cipher, extensions) -> str:
    return ",".join([str(version), str(cipher), _join(extensions)])


def md5(s: str) -> str:
    # MD5 is used here only as a fingerprint identifier, as the JA3 spec defines.
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()
