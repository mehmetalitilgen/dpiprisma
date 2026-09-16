#!/usr/bin/env python3
"""
Basic TLS 1.3 ClientHello builder and ServerHello parser.
"""
import os
import sys
import socket
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from profiles import PROFILES, DEFAULT, Profile


def u8(b: bytes) -> bytes:
    """1 baytlik uzunluk prefixi ekler."""
    assert len(b) < 2**8
    return struct.pack("!B", len(b)) + b


def u16(b: bytes) -> bytes:
    """2 baytlik uzunluk prefixi ekler."""
    assert len(b) < 2**16
    return struct.pack("!H", len(b)) + b


def u24(b: bytes) -> bytes:
    """3 baytlik uzunluk prefixi ekler (handshake mesajlari icin)."""
    n = len(b)
    return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + b


def ext(ext_type: int, body: bytes) -> bytes:
    """Bir TLS eklentisi: type(2) + length(2) + body."""
    return struct.pack("!H", ext_type) + u16(body)


def x25519_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
    )
    return pub



def build_client_hello(hostname: str, profile: Profile = DEFAULT) -> bytes:
    pubkey = x25519_keypair()

    # --- body
    client_version = struct.pack("!H", 0x0303)        # TLS 1.2 (uyumluluk)
    client_random = os.urandom(32)
    session_id = u8(os.urandom(32))                   # TLS 1.3 "middlebox compat"
    ciphers = u16(b"".join(struct.pack("!H", c) for c in profile.cipher_suites))
    compression = u8(b"\x00")                         # sadece 'null'

    # --- extensions
    exts = b""

    # 0x0000 server_name (SNI)
    sni_entry = b"\x00" + u16(hostname.encode())      # type 0 = host_name
    exts += ext(0x0000, u16(sni_entry))

    # 0x000B ec_point_formats -> uncompressed
    exts += ext(0x000B, u8(b"\x00"))

    # 0x000A supported_groups
    exts += ext(0x000A, u16(b"".join(struct.pack("!H", g) for g in profile.groups)))

    # 0x000D signature_algorithms
    exts += ext(0x000D, u16(b"".join(struct.pack("!H", s) for s in profile.sig_algs)))

    # 0x0010 ALPN
    alpn_list = b"".join(u8(p.encode()) for p in profile.alpn)
    exts += ext(0x0010, u16(alpn_list))

    # 0x0017 extended_master_secret (bos)
    exts += ext(0x0017, b"")

    # 0x002B supported_versions -> TLS 1.3, TLS 1.2
    exts += ext(0x002B, u8(struct.pack("!HH", 0x0304, 0x0303)))

    # 0x002D psk_key_exchange_modes -> psk_dhe_ke
    exts += ext(0x002D, u8(b"\x01"))

    # 0x0033 key_share -> x25519
    entry = struct.pack("!H", 0x001D) + u16(pubkey)
    exts += ext(0x0033, u16(entry))

    body = (client_version + client_random + session_id
            + ciphers + compression + u16(exts))

    handshake = b"\x01" + u24(body)                   # 0x01 = client_hello
    record = b"\x16\x03\x01" + u16(handshake)         # handshake record, legacy 0x0301
    return record


# ------------------------------------------------------------ ServerHello

def parse_server_hello(data: bytes) -> dict:
    """Dogrulama icin minimal ServerHello ayristirici."""
    if len(data) < 5 or data[0] != 0x16:
        return {"error": f"handshake record degil: type=0x{data[0]:02x}"}
    body = data[5:]
    if body[0] != 0x02:
        return {"error": f"server_hello degil: type=0x{body[0]:02x}"}

    i = 4 + 2 + 32                     # hdr + version + random
    sid_len = body[i]
    i += 1 + sid_len
    cipher = struct.unpack("!H", body[i:i + 2])[0]
    i += 2 + 1                         # + compression

    ext_len = struct.unpack("!H", body[i:i + 2])[0]
    i += 2
    end, chosen_version = i + ext_len, 0x0303
    while i < end:
        etype, elen = struct.unpack("!HH", body[i:i + 4])
        if etype == 0x002B:            # supported_versions
            chosen_version = struct.unpack("!H", body[i + 4:i + 6])[0]
        i += 4 + elen

    return {"version": f"0x{chosen_version:04x}", "cipher": f"0x{cipher:04x}"}


def send_hello(host: str, port: int = 443, timeout: float = 10.0,
               profile: Profile = DEFAULT) -> dict:
    hello = build_client_hello(host, profile)
    with socket.create_connection((host, port), timeout) as s:
        s.sendall(hello)
        head = s.recv(5)
        length = struct.unpack("!H", head[3:5])[0]
        rest = b""
        while len(rest) < length:
            chunk = s.recv(length - len(rest))
            if not chunk:
                break
            rest += chunk
    return parse_server_hello(head + rest)


def hexdump(data: bytes, width: int = 16) -> str:
    out = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{off:04x}  {hexs}  {text}")
    return "\n".join(out)


if __name__ == "__main__":

    host = sys.argv[1] if len(sys.argv) > 1 else "google.com"

    profile = PROFILES[sys.argv[2]] if len(sys.argv) > 2 else DEFAULT

    ch = build_client_hello(host, profile)
    print(f"ClientHello [{profile.name}]: {len(ch)} bayt (ilk 128 gosteriliyor)\n")
    print(hexdump(ch[:128]))

    try:
        print("\nSunucuya gonderiliyor...")
        print("ServerHello:", send_hello(host, profile=profile))
    except OSError as e:
        print(f"\nBaglanti kurulamadi: {e}")