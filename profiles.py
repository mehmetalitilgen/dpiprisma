"""
TLS parmak izi profilleri.

Bir ClientHello'yu tanimlayan listeler burada durur. Listelerin SIRASI
onemlidir: sunucular ve DPI kutulari fingerprint'i (JA3/JA4) bu siradan
cikarir, yani siralamayi degistirmek istemciyi baska bir istemci yapar.
"""
from typing import NamedTuple


class Profile(NamedTuple):
    name: str
    cipher_suites: tuple
    groups: tuple
    sig_algs: tuple
    alpn: tuple


CHROME = Profile(
    name="chrome",
    cipher_suites=(
        0x1301,  # TLS_AES_128_GCM_SHA256           (TLS 1.3)
        0x1302,  # TLS_AES_256_GCM_SHA384           (TLS 1.3)
        0x1303,  # TLS_CHACHA20_POLY1305_SHA256     (TLS 1.3)
        0xC02B,  # ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02F,  # ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC02C,  # ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xC030,  # ECDHE_RSA_WITH_AES_256_GCM_SHA384
    ),
    groups=(
        0x001D,  # x25519
        0x0017,  # secp256r1
        0x0018,  # secp384r1
    ),
    sig_algs=(
        0x0403,  # ecdsa_secp256r1_sha256
        0x0804,  # rsa_pss_rsae_sha256
        0x0401,  # rsa_pkcs1_sha256
        0x0503,  # ecdsa_secp384r1_sha384
        0x0805,  # rsa_pss_rsae_sha384
        0x0501,  # rsa_pkcs1_sha384
        0x0806,  # rsa_pss_rsae_sha512
        0x0601,  # rsa_pkcs1_sha512
    ),
    alpn=("h2", "http/1.1"),
)

PROFILES = {CHROME.name: CHROME}
DEFAULT = CHROME
