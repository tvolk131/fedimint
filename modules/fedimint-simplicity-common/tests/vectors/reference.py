"""Independent, stdlib-only reference for the fixed consensus vectors.

Does not import, invoke, or parse any Fedimint/Simplicity implementation. Prints
JSON to stdout; normal Rust tests only read the committed JSON. Regeneration is
an explicit consensus-review action, never part of a test or build.
"""
import hashlib
import json
import struct


def sha(data):
    return hashlib.sha256(data).digest()


def big(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b"\xfd" + n.to_bytes(2, "big")
    if n <= 4294967295:
        return b"\xfe" + n.to_bytes(4, "big")
    return b"\xff" + n.to_bytes(8, "big")


def seq(items):
    return big(len(items)) + b"".join(items)


def blob(data):
    return big(len(data)) + data


def text(s):
    return blob(s.encode())


def extension(variant, data):
    return b"\x01" + big(variant) + blob(data)


def output(version, amount, cmr, state, recovery, ext=b""):
    return big(version) + big(amount) + cmr + state + blob(recovery) + ext


key = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
federation = b"\x99" * 32
asset_a, asset_b = b"\x44" * 32, b"\x55" * 32
legacy = output(0, 1000, b"\x11" * 32, b"\x22" * 32, b"\xde\xad")
bundle = seq([asset_a + big(253), asset_b + big(65536)]) + seq([asset_a, asset_b])
asset = output(1, 65536, b"\x11" * 32, b"\x22" * 32, b"\xde\xad", extension(0, bundle))


def actions(signature):
    creation = key + seq([big(1)]) + signature
    payload = seq([creation]) + seq([asset_a + big(10)]) + seq([asset_b + big(11)])
    return output(1, 0, bytes(32), bytes(32), b"", extension(1, payload))


def outputs(signature):
    return seq([big(4) + blob(legacy), big(4) + blob(asset), big(7) + blob(actions(signature))])


point = b"\x33" * 32 + big(253)
spends = seq([point + key])
nonce = b"\x88" * 8
namespace = sha(text("fedimint/simplicity/namespace/v1") + federation + big(4) + key)
wire = {
    "legacy_output": legacy.hex(),
    "asset_output": asset.hex(),
    "actions_output": actions(b"\x66" * 64).hex(),
    "outputs": outputs(b"\x66" * 64).hex(),
    "outpoint_hash": sha(point).hex(),
    "namespace": namespace.hex(),
    "asset_id_0": sha(text("fedimint/simplicity/asset/v1") + namespace + big(0)).hex(),
    "asset_id_253": sha(text("fedimint/simplicity/asset/v1") + namespace + big(253)).hex(),
    "sighash_v0": sha(text("fedimint/simplicity/intent/v0") + federation + big(4) + big(0) + spends + nonce + outputs(b"\x66" * 64)).hex(),
    "sighash_v1": sha(text("fedimint/simplicity/intent/v1") + federation + big(4) + spends + nonce + outputs(bytes(64))).hex(),
}

# name, source bits, target bits; these are protocol constants, not read from Rust.
jet_specs = [
    ("sig_hash_all", 0, 256), ("session_index", 0, 64), ("block_count", 0, 64),
    ("current_amount", 0, 64), ("current_cmr", 0, 256), ("current_state", 0, 256),
    ("current_index", 0, 32), ("input_count", 0, 32), ("output_count", 0, 32),
    ("output_amount", 32, 64), ("output_cmr", 32, 256), ("output_state", 32, 256),
    ("output_hash", 32, 256), ("output_module", 32, 16),
    ("creation_session", 0, 64), ("creation_block_count", 0, 64),
    ("input_amount", 32, 64), ("input_cmr", 32, 256), ("input_state", 32, 256),
    ("input_outpoint_hash", 32, 256), ("input_asset_quantity", 288, 64),
    ("output_asset_quantity", 288, 64), ("input_authority", 288, 1),
    ("output_authority", 288, 1), ("issued_quantity", 256, 64),
    ("burned_quantity", 256, 64), ("input_asset_count", 32, 32),
    ("output_asset_count", 32, 32), ("input_authority_count", 32, 32),
    ("output_authority_count", 32, 32), ("input_asset_id", 64, 256),
    ("output_asset_id", 64, 256), ("input_authority_id", 64, 256),
    ("output_authority_id", 64, 256), ("input_version", 32, 32),
    ("output_version", 32, 32),
]
jets = [dict(name="fm_" + name, encoding=((256 + i) << 7).to_bytes(2, "big").hex(),
             source=source, target=target, cmr=sha(("fedimint/simplicity/jet/v0/fm_" + name).encode()).hex(), cost=1000)
        for i, (name, source, target) in enumerate(jet_specs)]

# SHA-256 compression, independently spelled out for Simplicity tagged midstates.
K = [int(x, 16) for x in """
428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
""".split()]
IV = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")


def rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def compress(state, block):
    initial = list(struct.unpack(">8I", state))
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = w[i-15], w[i-2]
        w.append((w[i-16] + (rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3)) + w[i-7]
                  + (rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10))) & 0xffffffff)
    a, b, c, d, e, f, g, h = initial
    for k, word in zip(K, w):
        t1 = (h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) + ((e & f) ^ (~e & g)) + k + word) & 0xffffffff
        t2 = ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xffffffff
        a, b, c, d, e, f, g, h = (t1+t2) & 0xffffffff, a, b, c, (d+t1) & 0xffffffff, e, f, g
    return struct.pack(">8I", *[(x+y) & 0xffffffff for x, y in zip(initial, [a,b,c,d,e,f,g,h])])


# Sanity-check the reference compression against hashlib on a full padded block.
assert compress(IV, b"abc\x80" + bytes(52) + (24).to_bytes(8, "big")) == sha(b"abc")


def cmr_iv(name):
    tag = sha(("Simplicity\x1fCommitment\x1f" + name).encode())
    return compress(IV, tag + tag)


def comp(left, right):
    return compress(cmr_iv("comp"), left + right)


def pack(bits):
    bits += "0" * (-len(bits) % 8)
    return int(bits, 2).to_bytes(len(bits) // 8, "big").hex()


# Literal canonical DAG encodings: unit; session_index then unit;
# witness -> issued_quantity -> unit. Natural numbers: 1=0, 2=100,
# 3=101, 5=110001. Jet nodes start 11, then family 1 and the 8-bit opcode.
unit = cmr_iv("unit")
programs = [
    dict(name="unit", program="24", witness="", cmr=unit.hex(), cost=100, cells=0, frames=0, fee=102),
    dict(name="session", program=pack("101" + "11100000001" + "01001" + "00000" + "100" + "0"), witness="",
         cmr=comp(bytes.fromhex(jets[1]["cmr"]), unit).hex(), cost=1364, cells=64, frames=1, fee=106),
    dict(name="issuance", program=pack("110001" + "0111" + "11100011000" + "00000" + "100" + "0" + "01001" + "00000" + "100" + "0"), witness=asset_a.hex(),
         cmr=comp(comp(cmr_iv("witness"), bytes.fromhex(jets[24]["cmr"])), unit).hex(), cost=2076, cells=576, frames=2, fee=141),
]
print(json.dumps(dict(wire=wire, jets=jets, programs=programs), indent=2))
