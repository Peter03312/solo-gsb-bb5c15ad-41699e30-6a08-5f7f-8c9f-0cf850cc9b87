#!/usr/bin/env python3
"""审计快照签发与离线验真端到端示例（纯标准库，验签演示可选依赖 cryptography）。

覆盖：
1) 取签名公钥（GET /me/signing-key，复核人事先带外信任）；
2) 开封完成后封存人/见证人签发审计快照（POST /documents/{id}/audit-snapshot）：
   快照含资料编号、摘要、状态、开封/清除时刻、按原顺序排列且标明截止序号的
   审计记录——不含正文、不含公钥；返回快照 + 签名 + 公钥标识；
3) 离线复核人提交快照、签名与“事先信任的公钥”到公开验真接口
   （POST /audit-snapshots/verify，无需账号密钥），得到验真结果与截止序号；
4) 各类明确失败：改字段/改记录顺序/截断拼接、错误公钥、伪造包内公钥、
   不支持版本、无效公钥；
5) 交接后旧封存人不能再签发，新封存人签发的快照要用新封存人的公钥验证。

用法: python examples/demo_audit_snapshot.py [base_url]
"""
import base64
import datetime as dt
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def call(method: str, path: str, key: str | None = None, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json", **({"X-API-Key": key} if key else {})},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def in_hours(h: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=h)).isoformat()


def show(title: str, status: int, body) -> None:
    print(f"-- {title} -> {status}")
    print("   " + json.dumps(body, ensure_ascii=False)[:600])


def verify(snapshot, signature, trusted_public_key):
    """公开验真接口：不需要任何 X-API-Key。"""
    return call("POST", "/audit-snapshots/verify", payload={
        "snapshot": snapshot,
        "signature": signature,
        "trusted_public_key": trusted_public_key,
    })


def main() -> None:
    users = {}
    for name in ["snap-alice", "snap-bob", "snap-carol", "snap-dave", "snap-erin"]:
        _, body = call("POST", "/register", payload={"username": name})
        users[name] = body["api_key"]
    alice, bob, carol, dave, erin = (
        users[n] for n in
        ["snap-alice", "snap-bob", "snap-carol", "snap-dave", "snap-erin"]
    )

    # ------------------------------------------------------------------
    # 第 0 步：签发方公布公钥；复核人事先通过带外渠道取得并信任
    # ------------------------------------------------------------------
    print("== 第 0 步：签名公钥（复核人须事先信任，服务端不以包内公钥建立信任） ==")
    status, key_info = call("GET", "/me/signing-key", alice)
    show("alice 的签名公钥", status, key_info)
    trusted_pub = key_info["public_key"]
    assert status == 200

    # ------------------------------------------------------------------
    # 封存 -> 开封（两名见证人同意）
    # ------------------------------------------------------------------
    print("== 封存并走两票开封流程 ==")
    _, sealed = call("POST", "/documents", alice,
                     {"body": "审计快照示例正文：SNAPSHOT-DEMO-SECRET",
                      "witnesses": ["snap-bob", "snap-carol", "snap-dave"]})
    doc_id, digest = sealed["document_id"], sealed["digest"]

    _, req = call("POST", f"/documents/{doc_id}/open-requests", alice,
                  {"reason": "家庭会议后复核", "deadline": in_hours(24)})
    request_id = req["request_id"]
    call("POST", f"/open-requests/{request_id}/approve", bob, {"digest": digest})
    status, opened = call("POST", f"/open-requests/{request_id}/approve", carol,
                          {"digest": digest})
    print(f"-- 两票同意 -> {opened['status']}")

    # ------------------------------------------------------------------
    # 第 1 步：开封结算完成后，封存人签发审计快照
    # ------------------------------------------------------------------
    print("== 第 1 步：封存人签发审计快照 ==")
    status, pack = call("POST", f"/documents/{doc_id}/audit-snapshot", alice)
    show("签发返回（快照+签名+公钥标识，无正文、无公钥）", status, pack)
    assert status == 201
    snapshot, signature, key_id = pack["snapshot"], pack["signature"], pack["key_id"]
    assert "SNAPSHOT-DEMO-SECRET" not in json.dumps(pack, ensure_ascii=False)
    print(f"   快照状态={snapshot['status']}，截止序号={snapshot['cutoff_seq']}，"
          f"记录数={len(snapshot['records'])}，公钥标识={key_id}")

    # 指定见证人也可以签发
    status, wpack = call("POST", f"/documents/{doc_id}/audit-snapshot", bob)
    print(f"-- 当前见证人 bob 签发 -> {status}")

    # ------------------------------------------------------------------
    # 第 2 步：离线复核人用“事先信任的公钥”验真（无需账号密钥）
    # ------------------------------------------------------------------
    print("== 第 2 步：离线验真（公开接口，凭事先信任的公钥） ==")
    status, result = verify(snapshot, signature, trusted_pub)
    show("验真通过", status, result)
    assert status == 200 and result["valid"] is True
    assert result["cutoff_seq"] == snapshot["cutoff_seq"]
    assert result["trusted_key_id"] == key_id

    # ------------------------------------------------------------------
    # 第 3 步：各类篡改与攻击都必须明确失败
    # ------------------------------------------------------------------
    print("== 第 3 步：篡改/错误材料的明确失败 ==")

    def expect_fail(title, snap, sig, pub, reason):
        st, r = verify(snap, sig, pub)
        print(f"-- {title} -> {st} valid={r['valid']} reason={r['reason']}")
        assert st == 200 and r["valid"] is False and r["reason"] == reason, r

    import copy

    # 3.1 改摘要字段
    tampered = copy.deepcopy(snapshot)
    tampered["digest"] = "0" * 64
    expect_fail("篡改摘要", tampered, signature, trusted_pub, "signature_mismatch")

    # 3.2 打乱审计记录顺序
    tampered = copy.deepcopy(snapshot)
    tampered["records"][0], tampered["records"][-1] = (
        tampered["records"][-1], tampered["records"][0])
    expect_fail("记录顺序被打乱", tampered, signature, trusted_pub,
                "records_out_of_order")

    # 3.3 截断审计后伪造一致的截止序号（把并发后的状态与旧审计拼接）
    tampered = copy.deepcopy(snapshot)
    tampered["records"] = tampered["records"][:2]
    tampered["cutoff_seq"] = tampered["records"][-1]["seq"]
    expect_fail("截断记录并伪造截止序号（拼接）", tampered, signature, trusted_pub,
                "signature_mismatch")

    # 3.4 用别的账号公钥验证（复核人不信任的签发方）
    _, erin_key = call("GET", "/me/signing-key", erin)
    expect_fail("用错误公钥验证", snapshot, signature, erin_key["public_key"],
                "signature_mismatch")

    # 3.5 快照里夹带公钥：服务端拒绝，绝不以包内公钥建立信任
    tampered = copy.deepcopy(snapshot)
    tampered["public_key"] = trusted_pub
    expect_fail("快照包内自带公钥", tampered, signature, trusted_pub,
                "snapshot_malformed")

    # 3.6 不支持的版本
    tampered = copy.deepcopy(snapshot)
    tampered["version"] = "seal-audit-snapshot/v9"
    expect_fail("版本不支持", tampered, signature, trusted_pub,
                "version_unsupported")

    # 3.7 无效公钥（长度不对 / 乱码）
    expect_fail("公钥无效（31 字节）", snapshot, signature,
                base64.b64encode(b"x" * 31).decode(), "public_key_invalid")
    expect_fail("公钥无效（乱码）", snapshot, signature, "not-a-key!!!",
                "public_key_invalid")

    # 3.8 签名不匹配
    expect_fail("伪造签名", snapshot, base64.b64encode(b"x" * 64).decode(),
                trusted_pub, "signature_mismatch")

    # ------------------------------------------------------------------
    # 第 4 步：交接后旧封存人不得再签发
    # ------------------------------------------------------------------
    print("== 第 4 步：交接后旧封存人失权，新封存人另用其公钥 ==")
    _, sealed2 = call("POST", "/documents", alice,
                      {"body": "待交接资料正文：HANDOVER-SNAPSHOT-SECRET",
                       "witnesses": ["snap-bob", "snap-carol", "snap-dave"]})
    doc2 = sealed2["document_id"]
    _, inv = call("POST", f"/documents/{doc2}/handover-invitations", alice,
                  {"to_username": "snap-erin", "confirm_deadline": in_hours(1)})
    call("POST", f"/handover-invitations/{inv['invitation_id']}/confirm", erin)

    st, _ = call("POST", f"/documents/{doc2}/audit-snapshot", alice)
    print(f"-- 交接后旧封存人 alice 再签发 -> {st}（统一 403，不区分资料是否存在）")
    assert st == 403
    st, new_pack = call("POST", f"/documents/{doc2}/audit-snapshot", erin)
    print(f"-- 新封存人 erin 签发 -> {st}，issuer={new_pack['snapshot']['issuer']}")
    assert st == 201
    # 新封存人的快照必须用 erin 的公钥验证，alice 的公钥验不过
    st, r = verify(new_pack["snapshot"], new_pack["signature"], trusted_pub)
    print(f"-- 用旧封存人公钥验证新封存人签名 -> valid={r['valid']} ({r['reason']})")
    assert r["valid"] is False
    st, r = verify(new_pack["snapshot"], new_pack["signature"], erin_key["public_key"])
    print(f"-- 用新封存人公钥验证 -> valid={r['valid']}，截止序号={r['cutoff_seq']}")
    assert r["valid"] is True

    # 非参与方 / 不存在资料：统一 403
    st_nonexist, _ = call("POST", "/documents/999999/audit-snapshot", erin)
    print(f"-- 不存在资料 -> {st_nonexist}（与非参与方同语义）")
    assert st_nonexist == 403

    print("\n全部演示通过：快照可离线验真，任何篡改/错钥/错版本/无效公钥均明确失败。")


if __name__ == "__main__":
    main()
