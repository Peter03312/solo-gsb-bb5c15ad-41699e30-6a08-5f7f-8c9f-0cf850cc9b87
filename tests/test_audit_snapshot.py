"""审计快照签发与离线验真测试。

规则要点（规格）：
- 当前封存人或当前指定见证人可在到点开封、清除等结算完成后签发某份资料的
  审计快照；快照含资料编号、摘要、当前状态与开封/清除时刻、按原顺序排列
  且标明截止序号的审计记录；快照不含正文，也不含任何密钥；
- 签发返回快照、签名（Ed25519）与公钥标识 key_id（不含公钥）；
- 复核人提交快照、签名及事先信任的公钥到公开验真接口，得到验真结果与
  截止序号；服务端绝不以包内自带公钥建立信任；
- 字段被篡改、记录顺序被打乱、记录截断/拼接、签名不匹配、版本不支持、
  公钥无效均明确失败（valid=false + 原因码），验真接口无需账号密钥；
- 签发必须对应一个已提交的一致状态：状态、摘要与审计在同一写临界区读取，
  不能把并发操作后的状态与之前的审计拼接；
- 交接后旧封存人不得再签发；被替换掉的旧见证人不得再签发；非参与方与
  不存在资料沿用统一 403 拒绝语义；
- 签名密钥随库持久化，服务重启后旧签名仍可用同一公钥验证。
"""
import base64
import datetime as dt
import json
import threading
import time

import pytest

from conftest import auth, register, seal

BODY = "审计快照绝密正文 SNAPSHOT-SECRET"


def _in_hours(h: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=h)).isoformat()


def _in_seconds(s: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=s)).isoformat()


def _setup(client, names=("owner", "w1", "w2", "w3", "other")):
    keys = {n: register(client, n) for n in names}
    d = seal(client, keys["owner"], BODY, ["w1", "w2", "w3"])
    return keys, d["document_id"], d["digest"]


def _signing_key(client, key):
    r = client.get("/me/signing-key", headers=auth(key))
    assert r.status_code == 200, r.text
    info = r.json()
    assert info["algorithm"] == "Ed25519"
    assert info["key_id"].startswith("ed25519:")
    # 32 字节原始公钥的标准 base64
    assert len(base64.b64decode(info["public_key"])) == 32
    return info


def _issue(client, key, doc_id, expected=201):
    r = client.post(f"/documents/{doc_id}/audit-snapshot", headers=auth(key))
    assert r.status_code == expected, r.text
    return r


def _verify(client, snapshot, signature, pubkey):
    return client.post(
        "/audit-snapshots/verify",
        json={"snapshot": snapshot, "signature": signature,
              "trusted_public_key": pubkey},
    )


# ---------------------------------------------------------------------------
# 密钥
# ---------------------------------------------------------------------------


def test_signing_key_stable_and_requires_auth(client):
    keys, _, _ = _setup(client)
    r = client.get("/me/signing-key")
    assert r.status_code == 401
    info1 = _signing_key(client, keys["owner"])
    info2 = _signing_key(client, keys["owner"])
    # 密钥一经生成稳定不变
    assert info1 == info2
    # 不同账号密钥不同
    other = _signing_key(client, keys["other"])
    assert other["key_id"] != info1["key_id"]


# ---------------------------------------------------------------------------
# 签发：内容、权限、不留正文
# ---------------------------------------------------------------------------


def test_issue_snapshot_sealed_shape_and_no_body(client):
    keys, doc_id, digest = _setup(client)
    pack = _issue(client, keys["owner"], doc_id).json()
    snap = pack["snapshot"]

    assert set(pack.keys()) == {"snapshot", "signature", "key_id", "algorithm",
                                "signature_format"}
    assert pack["algorithm"] == "Ed25519"
    # 响应不含公钥，只给公钥标识
    assert "public_key" not in json.dumps(pack)
    assert pack["key_id"].startswith("ed25519:")
    assert len(base64.b64decode(pack["signature"])) == 64

    assert tuple(snap.keys()) == (
        "version", "document_id", "digest", "status", "opened_at", "purged_at",
        "issued_at", "issuer", "cutoff_seq", "records",
    )
    assert snap["version"] == "seal-audit-snapshot/v1"
    assert snap["document_id"] == doc_id
    assert snap["digest"] == digest
    assert snap["status"] == "sealed"
    assert snap["opened_at"] is None
    assert snap["purged_at"] is None
    assert snap["issuer"] == "owner"
    assert snap["cutoff_seq"] == snap["records"][-1]["seq"]
    # 封存时只有 seal 一条记录
    assert [r["action"] for r in snap["records"]] == ["seal"]
    # 记录按原顺序、序号严格递增；字段形状固定
    seqs = [r["seq"] for r in snap["records"]]
    assert seqs == sorted(set(seqs))
    for rec in snap["records"]:
        assert tuple(rec.keys()) == ("seq", "at", "action", "actor", "detail")
    # 快照与签名的任何地方都不含正文
    assert BODY not in json.dumps(pack, ensure_ascii=False)
    assert BODY.encode().hex() not in json.dumps(pack)


def test_witness_may_issue_nonparties_and_missing_doc_uniform_403(client):
    keys, doc_id, _ = _setup(client)
    # 三名指定见证人均可签发
    for w in ("w1", "w2", "w3"):
        assert _issue(client, keys[w], doc_id).status_code == 201
    # 非参与方 -> 403
    assert _issue(client, keys["other"], doc_id, expected=403).status_code == 403
    # 不存在资料 -> 同样 403（不区分是否存在）
    r1 = client.post("/documents/999999/audit-snapshot", headers=auth(keys["owner"]))
    r2 = client.post("/documents/999999/audit-snapshot", headers=auth(keys["other"]))
    assert r1.status_code == r2.status_code == 403
    # 无/错密钥 -> 401
    assert client.post(f"/documents/{doc_id}/audit-snapshot").status_code == 401
    assert client.post(
        f"/documents/{doc_id}/audit-snapshot", headers=auth("deadbeef")
    ).status_code == 401


def test_snapshot_audit_trail_excludes_its_own_issuance_record(client):
    keys, doc_id, _ = _setup(client)
    p1 = _issue(client, keys["owner"], doc_id).json()
    p2 = _issue(client, keys["owner"], doc_id).json()
    # 第二次快照的截止序号与记录是“签发前”的状态：包含第一次签发留痕，
    # 但不含第二次自身；两次快照内容因此可被独立验证。
    assert p2["snapshot"]["cutoff_seq"] > p1["snapshot"]["cutoff_seq"]
    actions = [r["action"] for r in p2["snapshot"]["records"]]
    assert actions.count("audit_snapshot_issued") == 1
    pub = _signing_key(client, keys["owner"])["public_key"]
    assert _verify(client, p1["snapshot"], p1["signature"], pub).json()["valid"]
    assert _verify(client, p2["snapshot"], p2["signature"], pub).json()["valid"]


# ---------------------------------------------------------------------------
# 开封/清除后的快照
# ---------------------------------------------------------------------------


def _open_doc(client, keys, doc_id, digest, *, earliest=None):
    payload = {"reason": "快照测试开封", "deadline": _in_hours(2)}
    if earliest is not None:
        payload["earliest_open_at"] = earliest
    r = client.post(f"/documents/{doc_id}/open-requests", json=payload,
                    headers=auth(keys["owner"]))
    assert r.status_code == 201, r.text
    req_id = r.json()["request_id"]
    client.post(f"/open-requests/{req_id}/approve", json={"digest": digest},
                headers=auth(keys["w1"]))
    r = client.post(f"/open-requests/{req_id}/approve", json={"digest": digest},
                    headers=auth(keys["w2"]))
    return req_id, r


def test_snapshot_after_opened_contains_timestamps_and_full_trail(client):
    keys, doc_id, digest = _setup(client)
    req_id, r = _open_doc(client, keys, doc_id, digest)
    assert r.json()["status"] == "opened"
    pack = _issue(client, keys["owner"], doc_id).json()
    snap = pack["snapshot"]
    assert snap["status"] == "opened"
    assert snap["opened_at"] is not None
    assert snap["purged_at"] is None
    assert [x["action"] for x in snap["records"]] == [
        "seal", "open_request_created", "approval", "approval", "opened",
    ]
    assert snap["cutoff_seq"] == snap["records"][-1]["seq"]
    # 即使已开封，快照也不含正文
    assert BODY not in json.dumps(pack, ensure_ascii=False)


def test_snapshot_after_purge_contains_both_times_no_body(client):
    keys, doc_id, digest = _setup(client)
    _open_doc(client, keys, doc_id, digest)
    # 安排 1 秒后清除并等待到点
    client.put(f"/documents/{doc_id}/purge", json={"purge_at": _in_seconds(1)},
               headers=auth(keys["owner"]))
    for _ in range(40):
        got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
        if got["status"] == "purged":
            break
        time.sleep(0.1)
    assert got["status"] == "purged"

    pack = _issue(client, keys["w1"], doc_id).json()
    snap = pack["snapshot"]
    assert snap["status"] == "purged"
    assert snap["opened_at"] is not None
    assert snap["purged_at"] == got["purged_at"]
    actions = [x["action"] for x in snap["records"]]
    assert actions[-1] == "purged"
    assert "purge_scheduled" in actions
    assert BODY not in json.dumps(pack, ensure_ascii=False)

    # 快照与 /audit 完全一致（同一已提交状态）
    audit = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).json()
    audit_actions = [x["action"] for x in audit["records"]
                     if x["action"] != "audit_snapshot_issued"]
    assert actions == audit_actions[:len(actions)]


def test_issue_triggers_due_settlement_and_snapshots_committed_state(client):
    """停机期间到点：未跑扫描器时签发也必须先结算，再对一致状态出快照。"""
    keys, doc_id, digest = _setup(client)
    # 最早开封时刻 1 秒后，先攒两票进入 waiting
    req_id, r = _open_doc(client, keys, doc_id, digest, earliest=_in_seconds(1))
    assert r.json()["status"] == "waiting"
    time.sleep(1.2)
    # 不触发任何其他请求，直接签发：临界区必须先确定性开封
    pack = _issue(client, keys["owner"], doc_id).json()
    snap = pack["snapshot"]
    assert snap["status"] == "opened"
    assert snap["opened_at"] is not None
    assert snap["records"][-1]["action"] == "opened"
    pub = _signing_key(client, keys["owner"])["public_key"]
    assert _verify(client, snap, pack["signature"], pub).json()["valid"]


def test_issue_settles_expired_request_before_snapshot(client):
    """过截止时刻仍 pending 的请求，在签发临界区内先按原规则失效，
    快照必须包含 request_expired（已提交一致状态），资料仍为 sealed。"""
    keys, doc_id, _ = _setup(client)
    r = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "快照签发时到期", "deadline": _in_seconds(1)},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 201
    time.sleep(1.2)  # 不跑扫描，直接等截止时刻过去
    pack = _issue(client, keys["owner"], doc_id).json()
    snap = pack["snapshot"]
    assert snap["status"] == "sealed"
    assert snap["opened_at"] is None
    actions = [x["action"] for x in snap["records"]]
    assert actions[-1] == "request_expired"
    # request_expired 已随签发事务提交（随后查询也能看到）
    audit = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).json()
    assert any(x["action"] == "request_expired" for x in audit["records"])
    pub = _signing_key(client, keys["owner"])["public_key"]
    assert _verify(client, snap, pack["signature"], pub).json()["valid"]


# ---------------------------------------------------------------------------
# 验真：成功与各类篡改
# ---------------------------------------------------------------------------


def _issue_verified(client, keys, doc_id, issuer="owner"):
    pub = _signing_key(client, keys[issuer])["public_key"]
    pack = _issue(client, keys[issuer], doc_id).json()
    ok = _verify(client, pack["snapshot"], pack["signature"], pub).json()
    assert ok["valid"] is True
    assert ok["reason"] == "ok"
    assert ok["cutoff_seq"] == pack["snapshot"]["cutoff_seq"]
    assert ok["trusted_key_id"] == pack["key_id"]
    return pack, pub


def test_verify_valid_envelope_and_public_verify(client):
    keys, doc_id, _ = _setup(client)
    pack, pub = _issue_verified(client, keys, doc_id)
    # 验真接口无需任何账号密钥
    bare = client.post(
        "/audit-snapshots/verify",
        json={"snapshot": pack["snapshot"], "signature": pack["signature"],
              "trusted_public_key": pub},
    )
    assert bare.status_code == 200
    assert bare.json()["valid"] is True


def test_verify_accepts_pem_public_key(client):
    from cryptography.hazmat.primitives import serialization

    keys, doc_id, _ = _setup(client)
    pack = _issue(client, keys["owner"], doc_id).json()
    raw = base64.b64decode(_signing_key(client, keys["owner"])["public_key"])
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pem = Ed25519PublicKey.from_public_bytes(raw).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    r = _verify(client, pack["snapshot"], pack["signature"], pem)
    assert r.json()["valid"] is True


def test_verify_rejects_tampered_fields(client):
    keys, doc_id, _ = _setup(client)
    pack, pub = _issue_verified(client, keys, doc_id)

    def verify_with(mutate):
        snap = json.loads(json.dumps(pack["snapshot"]))
        mutate(snap)
        return _verify(client, snap, pack["signature"], pub).json()

    # 改摘要 -> 签名不匹配
    r = verify_with(lambda s: s.update(digest="0" * 64))
    assert r["valid"] is False and r["reason"] == "signature_mismatch"
    # 改状态
    r = verify_with(lambda s: s.update(status="opened"))
    assert r["reason"] == "signature_mismatch"
    # 改资料编号
    r = verify_with(lambda s: s.update(document_id=999))
    assert r["reason"] == "signature_mismatch"
    # 改开封/清除时刻
    r = verify_with(lambda s: s.update(opened_at="2026-10-01T00:00:00+00:00"))
    assert r["reason"] == "signature_mismatch"
    # 改记录内容（detail）
    def m(s):
        s["records"][-1]["detail"] = "伪造"
    assert verify_with(m)["reason"] == "signature_mismatch"
    # 改签发人
    r = verify_with(lambda s: s.update(issuer="mallory"))
    assert r["reason"] == "signature_mismatch"


def test_verify_rejects_record_reordering_and_splicing(client):
    keys, doc_id, digest = _setup(client)
    _open_doc(client, keys, doc_id, digest)
    pack, pub = _issue_verified(client, keys, doc_id)

    # 打乱记录顺序 -> records_out_of_order
    snap = json.loads(json.dumps(pack["snapshot"]))
    snap["records"][0], snap["records"][-1] = snap["records"][-1], snap["records"][0]
    r = _verify(client, snap, pack["signature"], pub).json()
    assert r["valid"] is False and r["reason"] == "records_out_of_order"

    # 删掉最后一条：截止序号仍指向被删记录 -> cutoff_seq_mismatch
    snap = json.loads(json.dumps(pack["snapshot"]))
    del snap["records"][-1]
    r = _verify(client, snap, pack["signature"], pub).json()
    assert r["reason"] == "cutoff_seq_mismatch"

    # 截断后伪造一致的截止序号（拼接旧审计）-> 签名不匹配
    snap = json.loads(json.dumps(pack["snapshot"]))
    snap["records"] = snap["records"][:2]
    snap["cutoff_seq"] = snap["records"][-1]["seq"]
    r = _verify(client, snap, pack["signature"], pub).json()
    assert r["valid"] is False and r["reason"] == "signature_mismatch"

    # 伪造更大的截止序号（超出发出的记录）
    snap = json.loads(json.dumps(pack["snapshot"]))
    snap["cutoff_seq"] += 1
    r = _verify(client, snap, pack["signature"], pub).json()
    assert r["reason"] == "cutoff_seq_mismatch"


def test_verify_rejects_bad_signature_and_wrong_key(client):
    keys, doc_id, _ = _setup(client)
    pack, pub = _issue_verified(client, keys, doc_id)
    other_pub = _signing_key(client, keys["other"])["public_key"]

    # 他人公钥 -> signature_mismatch
    r = _verify(client, pack["snapshot"], pack["signature"], other_pub).json()
    assert r["valid"] is False and r["reason"] == "signature_mismatch"
    # 乱码签名
    r = _verify(client, pack["snapshot"], base64.b64encode(b"x" * 64).decode(),
                pub).json()
    assert r["reason"] == "signature_mismatch"
    # 非法 base64 签名
    r = _verify(client, pack["snapshot"], "@@not-base64@@", pub).json()
    assert r["reason"] == "signature_mismatch"


def test_verify_rejects_invalid_public_key(client):
    keys, doc_id, _ = _setup(client)
    pack, _ = _issue_verified(client, keys, doc_id)
    # 非 base64 / 长度不对 -> 公钥无效
    for bad in ["not-a-key!!!", "   ", base64.b64encode(b"x" * 31).decode(),
                base64.b64encode(b"x" * 33).decode(),
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"]:
        r = _verify(client, pack["snapshot"], pack["signature"], bad).json()
        assert r["valid"] is False and r["reason"] == "public_key_invalid", bad
    # 注：Ed25519 对任意 32 字节串都接受为编码点（含全 0xFF），非法曲线点
    # 会在验签阶段体现为 signature_mismatch 而非公钥解析失败——此时也明确
    # 不通：
    r = _verify(client, pack["snapshot"], pack["signature"],
                base64.b64encode(bytes([0xFF] * 32)).decode()).json()
    assert r["valid"] is False


def test_verify_rejects_unsupported_version(client):
    keys, doc_id, _ = _setup(client)
    pack, pub = _issue_verified(client, keys, doc_id)
    snap = json.loads(json.dumps(pack["snapshot"]))
    snap["version"] = "seal-audit-snapshot/v9"
    r = _verify(client, snap, pack["signature"], pub).json()
    assert r["valid"] is False and r["reason"] == "version_unsupported"
    # 缺失 version
    snap = json.loads(json.dumps(pack["snapshot"]))
    del snap["version"]
    r = _verify(client, snap, pack["signature"], pub).json()
    assert r["valid"] is False and r["reason"] == "snapshot_malformed"


def test_verify_rejects_snapshot_carrying_public_key(client):
    """包内自带公钥必须被拒绝：不能以自带公钥建立信任。"""
    keys, doc_id, _ = _setup(client)
    pack, pub = _issue_verified(client, keys, doc_id)

    snap = json.loads(json.dumps(pack["snapshot"]))
    snap["public_key"] = pub
    r = _verify(client, snap, pack["signature"], pub).json()
    assert r["valid"] is False and r["reason"] == "snapshot_malformed"

    # 少字段同样拒绝
    snap = json.loads(json.dumps(pack["snapshot"]))
    del snap["digest"]
    r = _verify(client, snap, pack["signature"], pub).json()
    assert r["valid"] is False and r["reason"] == "snapshot_malformed"

    # snapshot 不是对象
    r = _verify(client, [1, 2, 3], pack["signature"], pub).json()
    assert r["valid"] is False and r["reason"] == "snapshot_malformed"


def test_verify_request_envelope_validation(client):
    # 缺字段 / 空字段 -> 422（请求本身不成形）
    r = client.post("/audit-snapshots/verify", json={"snapshot": {}})
    assert r.status_code == 422
    r = client.post("/audit-snapshots/verify",
                    json={"snapshot": {}, "signature": "", "trusted_public_key": ""})
    assert r.status_code == 422
    # 422 错误体不得回显敏感内容
    assert BODY not in r.text


# ---------------------------------------------------------------------------
# 交接 / 替换见证人后旧参与方失权
# ---------------------------------------------------------------------------


def test_old_owner_cannot_issue_after_handover(client):
    keys, doc_id, _ = _setup(client)
    r = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "other", "confirm_deadline": _in_hours(1)},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 201
    inv_id = r.json()["invitation_id"]
    r = client.post(f"/handover-invitations/{inv_id}/confirm", headers=auth(keys["other"]))
    assert r.status_code == 200

    # 旧封存人立即不能签发
    assert _issue(client, keys["owner"], doc_id, expected=403).status_code == 403
    # 新封存人与见证人可以
    assert _issue(client, keys["other"], doc_id).status_code == 201
    assert _issue(client, keys["w1"], doc_id).status_code == 201
    # 新封存人签发的快照：issuer 是新人，旧公钥验不过、新公钥能验过
    pack = _issue(client, keys["other"], doc_id).json()
    assert pack["snapshot"]["issuer"] == "other"
    old_pub = _signing_key(client, keys["owner"])["public_key"]
    new_pub = _signing_key(client, keys["other"])["public_key"]
    assert _verify(client, pack["snapshot"], pack["signature"],
                   old_pub).json()["reason"] == "signature_mismatch"
    assert _verify(client, pack["snapshot"], pack["signature"],
                   new_pub).json()["valid"] is True


def test_replaced_witness_cannot_issue(client):
    keys, doc_id, _ = _setup(client, names=("owner", "w1", "w2", "w3", "new", "other"))
    r = client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w3", "new_witness": "new"},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 200
    # 旧见证人立即失去签发资格
    assert _issue(client, keys["w3"], doc_id, expected=403).status_code == 403
    # 新见证人可以
    assert _issue(client, keys["new"], doc_id).status_code == 201


# ---------------------------------------------------------------------------
# 一致状态：签发快照必须匹配一个已提交历史，不能拼接
# ---------------------------------------------------------------------------


def test_snapshot_matches_committed_audit_prefix(client):
    keys, doc_id, digest = _setup(client)
    pack = _issue(client, keys["owner"], doc_id).json()
    snap = pack["snapshot"]
    audit = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).json()
    records = audit["records"]
    # 快照记录恰好是审计日志按序号的一个前缀，且每条字段逐一对应
    prefix = [r for r in records if r["id"] <= snap["cutoff_seq"]]
    assert len(prefix) == len(snap["records"])
    for got, rec in zip(snap["records"], prefix):
        assert got == {"seq": rec["id"], "at": rec["at"], "action": rec["action"],
                       "actor": rec["actor"], "detail": rec["detail"]}
    # 截止序号之后的记录不得出现在快照里
    assert all(r["seq"] <= snap["cutoff_seq"] for r in snap["records"])

    # 再来一次开封流程后签发：旧快照仍能验证（历史不可变），新快照前缀更长
    _open_doc(client, keys, doc_id, digest)
    pack2 = _issue(client, keys["owner"], doc_id).json()
    pub = _signing_key(client, keys["owner"])["public_key"]
    assert _verify(client, pack["snapshot"], pack["signature"], pub).json()["valid"]
    assert _verify(client, pack2["snapshot"], pack2["signature"], pub).json()["valid"]
    assert pack2["snapshot"]["cutoff_seq"] > snap["cutoff_seq"]


def test_snapshot_during_concurrent_approval_is_consistent(client):
    """并发签发与第二票同意赛跑：快照要么含 opened，要么不含，绝不拼接。"""
    import socket

    import httpx
    import uvicorn

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    from app.main import app

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    end = time.time() + 10
    while time.time() < end:
        try:
            if httpx.get(base + "/health", timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("server did not start")

    try:
        with httpx.Client(timeout=10) as c:
            def reg(n):
                return c.post(base + "/register", json={"username": n}).json()["api_key"]

            owner, w1, w2, w3 = (reg(f"cc-{n}") for n in ("o", "1", "2", "3"))
            import hashlib

            dg = hashlib.sha256(BODY.encode()).hexdigest()
            doc_id = c.post(base + "/documents",
                            json={"body": BODY, "witnesses": ["cc-1", "cc-2", "cc-3"]},
                            headers={"X-API-Key": owner}).json()["document_id"]
            deadline = _in_hours(2)
            req_id = c.post(f"{base}/documents/{doc_id}/open-requests",
                            json={"reason": "并发快照", "deadline": deadline},
                            headers={"X-API-Key": owner}).json()["request_id"]
            c.post(f"{base}/open-requests/{req_id}/approve", json={"digest": dg},
                   headers={"X-API-Key": w1})
            pub = c.get(base + "/me/signing-key",
                        headers={"X-API-Key": owner}).json()["public_key"]

        barrier = threading.Barrier(2)

        def second_approve():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(f"{base}/open-requests/{req_id}/approve",
                              json={"digest": dg}, headers={"X-API-Key": w2}).status_code

        def snapshot():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(f"{base}/documents/{doc_id}/audit-snapshot",
                              headers={"X-API-Key": owner}).json()

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=2) as pool:
            ap_code, pack = list(pool.map(lambda f: f(), [second_approve, snapshot]))

        snap = pack["snapshot"]
        actions = [r["action"] for r in snap["records"]]
        if snap["status"] == "opened":
            # 一致状态：opened 必须在记录里，opened_at 非空，验真通过
            assert "opened" in actions
            assert snap["opened_at"] is not None
        else:
            assert snap["status"] == "sealed"
            assert "opened" not in actions
            assert snap["opened_at"] is None
        # 无论哪种终态，快照对“事先信任的公钥”都必须验真通过
        with httpx.Client(timeout=10) as c:
            v = c.post(base + "/audit-snapshots/verify",
                       json={"snapshot": snap, "signature": pack["signature"],
                             "trusted_public_key": pub}).json()
        assert v["valid"] is True, v
        assert ap_code in (200, 409)
    finally:
        server.should_exit = True
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# 重启持久化
# ---------------------------------------------------------------------------


def test_old_signature_verifies_after_restart(tmp_path, monkeypatch):
    """密钥随库持久化：重启后旧签名仍可用同一公钥验证。"""
    import socket

    import httpx
    import uvicorn

    db = tmp_path / "snap-restart.db"
    monkeypatch.setenv("SEAL_DB_PATH", str(db))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    from app.main import app

    def serve():
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        srv = uvicorn.Server(cfg)
        t = threading.Thread(target=srv.run, daemon=True)
        t.start()
        base = f"http://127.0.0.1:{port}"
        end = time.time() + 10
        while time.time() < end:
            try:
                if httpx.get(base + "/health", timeout=1).status_code == 200:
                    return srv, t, base
            except Exception:
                time.sleep(0.1)
        pytest.fail("server did not start")

    srv1, t1, base1 = serve()
    try:
        with httpx.Client(timeout=10) as c:
            owner = c.post(base1 + "/register", json={"username": "rst-o"}).json()["api_key"]
            for n in ("rst-1", "rst-2", "rst-3"):
                c.post(base1 + "/register", json={"username": n})
            info = c.get(base1 + "/me/signing-key",
                         headers={"X-API-Key": owner}).json()
            doc_id = c.post(
                base1 + "/documents",
                json={"body": BODY, "witnesses": ["rst-1", "rst-2", "rst-3"]},
                headers={"X-API-Key": owner},
            ).json()["document_id"]
            pack = c.post(f"{base1}/documents/{doc_id}/audit-snapshot",
                          headers={"X-API-Key": owner}).json()
    finally:
        srv1.should_exit = True
        t1.join(timeout=5)

    # 重启（同一数据库文件）
    srv2, t2, base2 = serve()
    try:
        with httpx.Client(timeout=10) as c:
            v = c.post(base2 + "/audit-snapshots/verify",
                       json={"snapshot": pack["snapshot"], "signature": pack["signature"],
                             "trusted_public_key": info["public_key"]}).json()
            assert v["valid"] is True
            assert v["trusted_key_id"] == info["key_id"]
            # 同一账号用原 API Key 在新进程里拿到的仍是同一把公钥
            info2 = c.get(base2 + "/me/signing-key",
                          headers={"X-API-Key": owner}).json()
            assert info2["public_key"] == info["public_key"]
            assert info2["key_id"] == info["key_id"]
            # 重启后新签发的快照也可验证，且截止序号在旧快照之后
            pack2 = c.post(f"{base2}/documents/{doc_id}/audit-snapshot",
                           headers={"X-API-Key": owner}).json()
            v2 = c.post(base2 + "/audit-snapshots/verify",
                        json={"snapshot": pack2["snapshot"], "signature": pack2["signature"],
                              "trusted_public_key": info["public_key"]}).json()
            assert v2["valid"] is True
    finally:
        srv2.should_exit = True
        t2.join(timeout=5)
