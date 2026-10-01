#!/usr/bin/env python3
"""离线验真工具：完全不联系封存服务，仅凭事先信任的公钥本地校验审计快照。

信任锚点只有 --public-key 指定的本地公钥文件（由复核人事先通过带外渠道
取得，例如当面 U 盘、组织 PKI 发布）；本工具不会读取快照包内任何公钥，
快照结构上也不允许携带公钥字段。

用法：
  # 导出签发响应（curl 示例）
  curl -sS -X POST $BASE/documents/1/audit-snapshot \
      -H "X-API-Key: $OWNER_KEY" -o snapshot-pack.json
  # 导出事先信任的公钥（仅取 public_key 字段，一行标准 base64）
  curl -sS $BASE/me/signing-key -H "X-API-Key: $OWNER_KEY" \
      | python3 -c 'import json,sys;print(json.load(sys.stdin)["public_key"])' \
      > trusted-key.txt

  python3 examples/verify_snapshot_offline.py \
      --pack snapshot-pack.json --public-key trusted-key.txt

退出码：验真通过 0；任何失败（结构/版本/顺序/截止序号/公钥/签名）为 2。
依赖：cryptography（Ed25519）。
"""
import argparse
import base64
import binascii
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# 与服务端 app/signing.py 保持一致的两份独立实现（刻意不 import 服务代码，
# 体现“离线独立复核”）。
SNAPSHOT_VERSION = "seal-audit-snapshot/v1"
TOP_LEVEL_FIELDS = (
    "version", "document_id", "digest", "status", "opened_at", "purged_at",
    "issued_at", "issuer", "cutoff_seq", "records",
)
RECORD_FIELDS = ("seq", "at", "action", "actor", "detail")


def fail(reason: str, detail: str):
    print(json.dumps({"valid": False, "reason": reason, "detail": detail},
                     ensure_ascii=False))
    sys.exit(2)


def canonical_bytes(snapshot: dict) -> bytes:
    return json.dumps(
        snapshot, ensure_ascii=False, sort_keys=False,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def load_public_key(text: str) -> Ed25519PublicKey:
    text = text.strip()
    try:
        if "BEGIN" in text:
            key = serialization.load_pem_public_key(text.encode("ascii"))
        else:
            raw = base64.b64decode(text, validate=True)
            if len(raw) != 32:
                raise ValueError("Ed25519 公钥长度必须为 32 字节")
            key = Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, binascii.Error) as exc:
        fail("public_key_invalid", f"无法解析事先信任的公钥: {exc}")
    if not isinstance(key, Ed25519PublicKey):
        fail("public_key_invalid", "仅支持 Ed25519 公钥")
    return key


def main() -> None:
    ap = argparse.ArgumentParser(description="审计快照离线验真")
    ap.add_argument("--pack", required=True, help="签发接口返回的 JSON（含 snapshot/signature/key_id）")
    ap.add_argument("--snapshot", help="或直接提供 snapshot JSON（与 --signature 配合）")
    ap.add_argument("--signature", help="签名（标准 base64），与 --snapshot 配合")
    ap.add_argument("--public-key", required=True, help="事先信任的公钥文件（raw base64 一行，或 PEM）")
    args = ap.parse_args()

    with open(args.public_key, "r", encoding="utf-8") as f:
        public = load_public_key(f.read())

    if args.pack:
        with open(args.pack, "r", encoding="utf-8") as f:
            pack = json.load(f)
        snapshot, signature_b64 = pack["snapshot"], pack["signature"]
        bundle_key_id = pack.get("key_id")
    else:
        if not args.snapshot or not args.signature:
            ap.error("需要 --pack，或同时提供 --snapshot 与 --signature")
        with open(args.snapshot, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
        with open(args.signature, "r", encoding="utf-8") as f:
            signature_b64 = f.read().strip()
        bundle_key_id = None

    # ---- 结构 / 版本 ----
    if not isinstance(snapshot, dict):
        fail("snapshot_malformed", "快照必须是 JSON 对象")
    version = snapshot.get("version")
    if not isinstance(version, str):
        fail("snapshot_malformed", "缺少 version")
    if version != SNAPSHOT_VERSION:
        fail("version_unsupported", f"不支持的版本: {version}")
    if tuple(snapshot.keys()) != TOP_LEVEL_FIELDS:
        fail("snapshot_malformed", "顶层字段缺失、多余或顺序不符（快照不得自带公钥）")
    if snapshot["status"] not in ("sealed", "opened", "purged"):
        fail("snapshot_malformed", "status 非法")
    records = snapshot["records"]
    if not isinstance(records, list):
        fail("snapshot_malformed", "records 必须是数组")

    # ---- 记录顺序与截止序号 ----
    prev = 0
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or tuple(rec.keys()) != RECORD_FIELDS:
            fail("snapshot_malformed", f"第 {i + 1} 条记录字段缺失或多余")
        seq = rec["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            fail("records_out_of_order", f"第 {i + 1} 条记录序号不是整数")
        if seq <= prev:
            fail("records_out_of_order", "审计记录未按原顺序严格递增排列")
        prev = seq
    expected_cutoff = records[-1]["seq"] if records else 0
    if not isinstance(snapshot["cutoff_seq"], int) or snapshot["cutoff_seq"] != expected_cutoff:
        fail("cutoff_seq_mismatch", "截止序号与审计记录不一致")

    # ---- 签名（信任锚点只有本地公钥）----
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        fail("signature_mismatch", f"签名不是合法 base64: {exc}")
    try:
        public.verify(signature, canonical_bytes(snapshot))
    except InvalidSignature:
        fail("signature_mismatch", "签名与快照/信任公钥均不匹配")

    import hashlib

    raw_pub = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    trusted_key_id = "ed25519:" + hashlib.sha256(raw_pub).hexdigest()
    result = {
        "valid": True,
        "reason": "ok",
        "cutoff_seq": snapshot["cutoff_seq"],
        "document_id": snapshot["document_id"],
        "digest": snapshot["digest"],
        "status": snapshot["status"],
        "opened_at": snapshot["opened_at"],
        "purged_at": snapshot["purged_at"],
        "issued_at": snapshot["issued_at"],
        "issuer": snapshot["issuer"],
        "trusted_key_id": trusted_key_id,
        "record_count": len(records),
    }
    if bundle_key_id is not None:
        result["bundle_key_id"] = bundle_key_id
        result["key_id_matches_trust"] = (bundle_key_id == trusted_key_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
