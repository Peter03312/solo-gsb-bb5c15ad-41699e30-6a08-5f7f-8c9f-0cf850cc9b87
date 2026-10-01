"""审计快照的非对称签名与离线验真（Ed25519）。

设计要点：
- 每个本地账号一把 Ed25519 签名密钥（首次签发时惰性生成，私钥以原始字节
  落 SQLite）；重启后私钥仍在，旧签名随时可用同一公钥验证。
- 快照版本号 SNAPSHOT_VERSION 写入快照；验真只接受当前支持的版本，
  不支持的版本一律失败。
- 签名内容是快照的**规范化 JSON**（UTF-8、键序固定、紧凑分隔符）。
- 快照本身**不含公钥**：验真人必须提交“事先信任的公钥”，服务端绝不以
  包内自带公钥建立信任。
"""
import base64
import binascii
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SNAPSHOT_VERSION = "seal-audit-snapshot/v1"

# v1 顶层字段的固定顺序（canonical 序列化与结构校验共用）。
TOP_LEVEL_FIELDS = (
    "version",
    "document_id",
    "digest",
    "status",
    "opened_at",
    "purged_at",
    "issued_at",
    "issuer",
    "cutoff_seq",
    "records",
)
RECORD_FIELDS = ("seq", "at", "action", "actor", "detail")

# 验真失败原因（机器可读，写入 HTTP 200 响应的 reason 字段）。
REASON_VALID = None
REASON_VERSION_UNSUPPORTED = "version_unsupported"
REASON_SNAPSHOT_MALFORMED = "snapshot_malformed"
REASON_PUBLIC_KEY_INVALID = "public_key_invalid"
REASON_RECORDS_OUT_OF_ORDER = "records_out_of_order"
REASON_CUTOFF_MISMATCH = "cutoff_seq_mismatch"
REASON_SIGNATURE_MISMATCH = "signature_mismatch"


def b64encode(raw: bytes) -> str:
    """标准 base64（含填充），验真端用任意语言的标准 base64 解码即可。"""
    return base64.b64encode(raw).decode("ascii")


def b64decode(text: str) -> bytes:
    """严格标准 base64 解码；非法字符/错误填充抛 ValueError。"""
    if not isinstance(text, str) or not text:
        raise ValueError("空的 base64 输入")
    # validate=True：拒绝非字母表字符（含 URL-safe 的 -/_），防止歧义
    return base64.b64decode(text, validate=True)


def generate_keypair() -> tuple[str, str, str]:
    """生成一把新的 Ed25519 密钥，返回 (私钥 base64, 公钥 base64, key_id)。"""
    private = Ed25519PrivateKey.generate()
    priv_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64encode(priv_raw), b64encode(pub_raw), key_id_for_public(pub_raw)


def key_id_for_public(pub_raw: bytes) -> str:
    """公钥标识：ed25519: + 公钥原始字节的 SHA-256 十六进制摘要。"""
    return "ed25519:" + hashlib.sha256(pub_raw).hexdigest()


def load_private_key(priv_b64: str) -> Ed25519PrivateKey:
    priv_raw = b64decode(priv_b64)
    if len(priv_raw) != 32:
        raise ValueError("Ed25519 私钥长度必须为 32 字节")
    return Ed25519PrivateKey.from_private_bytes(priv_raw)


class UnsupportedKeyType(Exception):
    """解析出的公钥不是 Ed25519。"""


def parse_public_key(text: str) -> Ed25519PublicKey:
    """解析验真人提交的“事先信任的公钥”。

    接受两种形态：32 字节原始公钥的标准 base64（推荐，/me/signing-key
    返回的形态），或 PEM 文本（Ed25519 SubjectPublicKeyInfo）。任何无法
    解析、长度不对或非 Ed25519 的输入都抛 ValueError，由调用方映射为
    public_key_invalid。
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("空公钥")
    stripped = text.strip()
    try:
        if "BEGIN" in stripped:
            key = serialization.load_pem_public_key(stripped.encode("ascii"))
        else:
            raw = b64decode(stripped)
            if len(raw) != 32:
                raise ValueError("Ed25519 公钥长度必须为 32 字节")
            key = Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, binascii.Error, UnsupportedKeyType) as exc:
        raise ValueError(f"无效的 Ed25519 公钥: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise UnsupportedKeyType("仅支持 Ed25519 公钥")
    return key


def public_key_id(text: str) -> str:
    """信任公钥文本 -> key_id（解析失败抛 ValueError）。"""
    key = parse_public_key(text)
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return key_id_for_public(raw)


def canonical_snapshot_bytes(snapshot: dict[str, Any]) -> bytes:
    """快照规范化 JSON 字节：UTF-8、键序固定、紧凑分隔符、不转义非 ASCII。

    签发与验真共用同一份规范化逻辑；Python json 对 dict 按插入顺序输出，
    服务端组装时严格按 *_FIELDS 顺序构造，验真端可用同样规则自行复算。
    """
    return json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sign_snapshot(priv_b64: str, snapshot: dict[str, Any]) -> str:
    """用 Ed25519 私钥对规范化快照签名，返回标准 base64 签名。"""
    private = load_private_key(priv_b64)
    signature = private.sign(canonical_snapshot_bytes(snapshot))
    return b64encode(signature)


def _is_str_or_none(v: Any) -> bool:
    return v is None or isinstance(v, str)


class SnapshotError(Exception):
    """快照结构/顺序/截止序号校验失败；reason 为机器可读原因码。"""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


def validate_snapshot_shape(snapshot: Any) -> bool:
    """结构校验：字段集合、类型、记录形状与顺序、截止序号一致性。

    只做结构与顺序检查，不做任何密码学校验。返回 True 表示通过；
    不通过时抛 SnapshotError（携带原因码）。
    """
    if not isinstance(snapshot, dict):
        raise SnapshotError(REASON_SNAPSHOT_MALFORMED, "快照必须是 JSON 对象")
    version = snapshot.get("version")
    if not isinstance(version, str):
        raise SnapshotError(REASON_SNAPSHOT_MALFORMED, "快照缺少 version 字段")
    if version != SNAPSHOT_VERSION:
        raise SnapshotError(REASON_VERSION_UNSUPPORTED, "不支持的快照版本")
    if tuple(snapshot.keys()) != TOP_LEVEL_FIELDS:
        raise SnapshotError(
            REASON_SNAPSHOT_MALFORMED,
            "快照顶层字段缺失、多余或顺序不符（快照不得自带公钥）",
        )
    if not isinstance(snapshot["document_id"], int) or isinstance(snapshot["document_id"], bool):
        raise SnapshotError(REASON_SNAPSHOT_MALFORMED, "document_id 必须是整数")
    if not all(_is_str_or_none(snapshot[k]) for k in ("digest", "status", "opened_at",
                                                      "purged_at", "issued_at", "issuer")):
        raise SnapshotError(REASON_SNAPSHOT_MALFORMED, "快照标量字段类型错误")
    if not snapshot["digest"]:
        raise SnapshotError(REASON_SNAPSHOT_MALFORMED, "digest 不能为空")
    if snapshot["status"] not in ("sealed", "opened", "purged"):
        raise SnapshotError(REASON_SNAPSHOT_MALFORMED, "status 不是合法资料状态")
    if not snapshot["issued_at"] or not snapshot["issuer"]:
        raise SnapshotError(REASON_SNAPSHOT_MALFORMED, "issued_at/issuer 不能为空")
    cutoff = snapshot["cutoff_seq"]
    if not isinstance(cutoff, int) or isinstance(cutoff, bool) or cutoff < 0:
        raise SnapshotError(REASON_SNAPSHOT_MALFORMED, "cutoff_seq 必须是非负整数")

    records = snapshot["records"]
    if not isinstance(records, list):
        raise SnapshotError(REASON_SNAPSHOT_MALFORMED, "records 必须是数组")
    prev_seq = 0
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or tuple(rec.keys()) != RECORD_FIELDS:
            raise SnapshotError(REASON_SNAPSHOT_MALFORMED, f"第 {i + 1} 条记录字段缺失或多余")
        seq = rec["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise SnapshotError(REASON_RECORDS_OUT_OF_ORDER, f"第 {i + 1} 条记录序号不是整数")
        if not isinstance(rec["at"], str) or not rec["at"]:
            raise SnapshotError(REASON_SNAPSHOT_MALFORMED, f"第 {i + 1} 条记录 at 非法")
        if not isinstance(rec["action"], str) or not rec["action"]:
            raise SnapshotError(REASON_SNAPSHOT_MALFORMED, f"第 {i + 1} 条记录 action 非法")
        if not _is_str_or_none(rec["actor"]):
            raise SnapshotError(REASON_SNAPSHOT_MALFORMED, f"第 {i + 1} 条记录 actor 非法")
        if not isinstance(rec["detail"], str):
            raise SnapshotError(REASON_SNAPSHOT_MALFORMED, f"第 {i + 1} 条记录 detail 非法")
        # 必须按原顺序排列且序号严格递增
        if seq <= prev_seq:
            raise SnapshotError(REASON_RECORDS_OUT_OF_ORDER, "审计记录未按原顺序严格递增排列")
        prev_seq = seq

    # 截止序号必须与最后一条记录一致（无记录时必须为 0）
    expected_cutoff = records[-1]["seq"] if records else 0
    if cutoff != expected_cutoff:
        raise SnapshotError(REASON_CUTOFF_MISMATCH, "截止序号与审计记录不一致")
    return True


def verify_snapshot(snapshot: Any, signature_b64: str, trusted_public_key: str) -> str:
    """离线验真，返回失败原因码；成功返回 REASON_VALID（None）。

    顺序：版本与结构 -> 记录顺序/截止序号 -> 信任公钥有效性 -> 签名。
    只使用调用方提交的 trusted_public_key，绝不读取快照内任何公钥材料
    （快照结构上也不允许携带公钥字段）。
    """
    validate_snapshot_shape(snapshot)
    try:
        public = parse_public_key(trusted_public_key)
    except (ValueError, UnsupportedKeyType):
        return REASON_PUBLIC_KEY_INVALID
    try:
        signature = b64decode(signature_b64)
    except (ValueError, binascii.Error):
        return REASON_SIGNATURE_MISMATCH
    try:
        public.verify(signature, canonical_snapshot_bytes(snapshot))
    except InvalidSignature:
        return REASON_SIGNATURE_MISMATCH
    except (TypeError, ValueError):
        return REASON_SIGNATURE_MISMATCH
    return REASON_VALID
