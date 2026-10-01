from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class RegisterIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class SealIn(BaseModel):
    body: str = Field(min_length=1, max_length=1_000_000)
    witnesses: list[str] = Field(min_length=3, max_length=3)


class OpenRequestIn(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    deadline: datetime  # 必须带时区，例如 2026-10-01T12:00:00Z
    # 可选：最早开封时刻（须不早于提交时刻、且早于 deadline）。
    # 填写后两票在该时刻前集齐只会进入 waiting（待开封），到点自动开封。
    earliest_open_at: datetime | None = None

    @field_validator("deadline", "earliest_open_at")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        if v is not None and (v.tzinfo is None or v.utcoffset() is None):
            raise ValueError("时间字段必须带时区信息，例如 2026-10-01T12:00:00Z")
        return v

    @model_validator(mode="after")
    def _earliest_before_deadline(self) -> "OpenRequestIn":
        if self.earliest_open_at is not None and not self.earliest_open_at < self.deadline:
            raise ValueError("earliest_open_at 必须早于 deadline")
        return self


class ApproveIn(BaseModel):
    digest: str = Field(min_length=1, max_length=128)


class ReplaceWitnessIn(BaseModel):
    """封存人在资料未开封时替换一名指定见证人。"""

    old_witness: str = Field(min_length=1, max_length=64)
    new_witness: str = Field(min_length=1, max_length=64)


class RevokeIn(BaseModel):
    reason: str = Field(default="", max_length=2000)


class HandoverIn(BaseModel):
    """封存人就未开封资料发起交接邀请。"""

    to_username: str = Field(min_length=1, max_length=64)
    confirm_deadline: datetime  # 受让人确认截止时刻，必须带时区，例如 2026-10-01T12:00:00Z

    @field_validator("confirm_deadline")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("确认截止时刻必须带时区信息，例如 2026-10-01T12:00:00Z")
        return v


class PurgeIn(BaseModel):
    """封存人为资料安排（或改期）到期清除时刻。"""

    purge_at: datetime  # 到期清除时刻，必须带时区，例如 2026-10-01T12:00:00Z

    @field_validator("purge_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("清除时刻必须带时区信息，例如 2026-10-01T12:00:00Z")
        return v


class SnapshotVerifyIn(BaseModel):
    """离线复核人提交的验真材料：快照、签名与事先信任的公钥。

    snapshot 故意声明为 Any：服务端要把“快照不是 JSON 对象/缺字段”等
    情况也作为明确的验真失败（HTTP 200 + valid=false）返回，而不是
    请求层 422。服务端只以 trusted_public_key 验签，绝不从快照内取公钥
    建立信任；快照结构上也不允许携带公钥字段。
    """

    snapshot: Any
    signature: str = Field(min_length=1, max_length=256)
    trusted_public_key: str = Field(min_length=1, max_length=8192)
