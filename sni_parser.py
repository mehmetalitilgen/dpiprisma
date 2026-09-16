#!/usr/bin/env python3
"""
ClientHello icinden SNI (server_name) cikaran saglam ayristirici.


"""
import struct
from dataclasses import dataclass

TLS_HANDSHAKE = 0x16
CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000
NAME_TYPE_HOST = 0x00

# Bir ClientHello kaydinin ust siniri: 16KB kayit + baslik.
MAX_RECORD = 16384 + 5


class NeedMore(Exception):
    """Tampon henuz yeterli bayt icermiyor; soketten okumaya devam et."""


class Malformed(Exception):
    """Veri TLS ClientHello olarak ayristirilamiyor."""


class Fragmented(Malformed):
    """ClientHello birden fazla TLS kaydina bolunmus; birlestirme gerekir."""


class Reader:
    """Sinir kontrollu ileri-yonlu bayt okuyucu."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0:
            raise Malformed("negatif uzunluk")
        if self.remaining() < n:
            raise NeedMore(f"{n} bayt gerekli, {self.remaining()} mevcut")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        b = self.take(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]

    def vector8(self) -> bytes:
        """1 bayt uzunluk prefixli alan."""
        return self.take(self.u8())

    def vector16(self) -> bytes:
        """2 bayt uzunluk prefixli alan."""
        return self.take(self.u16())

    def skip_vector8(self):
        self.take(self.u8())

    def skip_vector16(self):
        self.take(self.u16())


@dataclass
class HelloInfo:
    sni: str | None
    legacy_version: int
    record_len: int
    alpn: list[str]


def is_grease(value: int) -> bool:
    """RFC 8701: 0x0a0a, 0x1a1a ... 0xfafa gibi degerler."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def parse_client_hello(data: bytes) -> HelloInfo:
    """
    Ham TLS kaydindan SNI ve ALPN cikarir.
    NeedMore -> daha fazla bayt oku. Malformed -> baglantiyi dusur.
    """
    r = Reader(data)

    # --- kayit katmani
    rec_type = r.u8()
    if rec_type != TLS_HANDSHAKE:
        raise Malformed(f"handshake kaydi degil: 0x{rec_type:02x}")
    r.take(2)                                  # legacy record version
    rec_len = r.u16()
    if rec_len == 0 or rec_len > MAX_RECORD:
        raise Malformed(f"gecersiz kayit uzunlugu: {rec_len}")
    if r.remaining() < rec_len:
        raise NeedMore(f"kayit {rec_len} bayt, {r.remaining()} mevcut")

    # Kayit sinirinin otesine tasmayi engellemek icin gorusu daralt.
    # Bu noktadan sonra kayit TAM; icerideki her eksiklik bozukluktur,
    # NeedMore dondurursek cagiran asla gelmeyecek bayt icin bekler.
    try:
        return _parse_hello_body(Reader(data[5:5 + rec_len]), rec_len)
    except NeedMore as e:
        raise Malformed(f"kayit icinde eksik alan: {e}") from None


def _parse_hello_body(r: Reader, rec_len: int) -> HelloInfo:
    # --- handshake basligi
    if r.u8() != CLIENT_HELLO:
        raise Malformed("client_hello degil")
    hs_len = r.u24()
    if hs_len > r.remaining():
        # ClientHello birden fazla kayda bolunmus; bu ayristirici
        # tek kayitlik hello bekler, yeniden birlestirme cagirana ait.
        raise Fragmented(f"handshake {hs_len} bayt, kayitta {r.remaining()}")

    legacy_version = r.u16()
    r.take(32)                                 # random
    r.skip_vector8()                           # session_id
    r.skip_vector16()                          # cipher_suites
    r.skip_vector8()                           # compression_methods

    # --- eklentiler (TLS 1.0 istemcilerinde hic olmayabilir)
    if r.remaining() == 0:
        return HelloInfo(None, legacy_version, rec_len + 5, [])

    ext_block = Reader(r.vector16())
    sni, alpn = None, []

    while ext_block.remaining() >= 4:
        etype = ext_block.u16()
        ebody = Reader(ext_block.vector16())

        if etype == EXT_SERVER_NAME and sni is None:
            sni = _parse_sni(ebody)
        elif etype == 0x0010:                  # ALPN
            alpn = _parse_alpn(ebody)

    return HelloInfo(sni, legacy_version, rec_len + 5, alpn)


def _parse_sni(r: Reader) -> str | None:
    """ServerNameList: her giris name_type(1) + name(2-prefixli)."""
    if r.remaining() == 0:
        return None                            # bos SNI gecerlidir
    lst = Reader(r.vector16())
    while lst.remaining() >= 3:
        name_type = lst.u8()
        name = lst.vector16()
        if name_type != NAME_TYPE_HOST:
            continue
        try:
            host = name.decode("ascii")
        except UnicodeDecodeError:
            raise Malformed("SNI ascii degil")
        if not host or len(host) > 253:
            raise Malformed(f"gecersiz hostname uzunlugu: {len(host)}")
        if any(c in host for c in "\x00 /\\"):
            raise Malformed("hostname yasakli karakter iceriyor")
        return host.rstrip(".").lower()
    return None


def _parse_alpn(r: Reader) -> list[str]:
    if r.remaining() == 0:
        return []
    lst = Reader(r.vector16())
    out = []
    while lst.remaining() >= 1:
        proto = lst.vector8()
        if proto:
            out.append(proto.decode("ascii", "replace"))
    return out


def read_sni_from_socket(conn, timeout: float = 5.0) -> HelloInfo:
    """
    Soketten ClientHello tamamlanana kadar okur.
    TLS'i sonlandirmaz; buffer'i cagirana geri dondurmek isterseniz
    HelloInfo yaninda ham baytlari da saklayin.
    """
    conn.settimeout(timeout)
    buf = b""
    while len(buf) < MAX_RECORD:
        try:
            return parse_client_hello(buf)
        except NeedMore:
            pass
        chunk = conn.recv(4096)
        if not chunk:
            raise Malformed("baglanti ClientHello tamamlanmadan kapandi")
        buf += chunk
    raise Malformed("ClientHello cok buyuk")


# ------------------------------------------------------------------- test

def _selftest():
    from client_hello import build_client_hello

    good = build_client_hello("Www.Örnek.Com".encode("idna").decode())
    print("normal      :", parse_client_hello(good))

    # Parcali teslimat: her prefiksin NeedMore vermesi beklenir
    partial_ok = all(
        _raises_needmore(good[:n]) for n in range(1, len(good))
    )
    print("parcali giris: tum kismi tamponlar NeedMore ->", partial_ok)

    # Bozuk girdiler
    for label, bad in [
        ("http istegi", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("sisirilmis uzunluk", b"\x16\x03\x01\xff\xff" + b"\x01" * 10),
        ("yalan ext uzunlugu", good[:100] + b"\xff\xff" + good[102:]),
        ("bos", b""),
    ]:
        try:
            print(f"{label:<20}:", parse_client_hello(bad))
        except (NeedMore, Malformed) as e:
            print(f"{label:<20}: {type(e).__name__} -> {e}")


def _raises_needmore(data: bytes) -> bool:
    try:
        parse_client_hello(data)
        return False
    except NeedMore:
        return True
    except Malformed:
        return False


if __name__ == "__main__":
    _selftest()