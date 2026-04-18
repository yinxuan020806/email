# -*- coding: utf-8 -*-
"""parse_import_text 解析逻辑：覆盖新增的"行末组名"等格式。"""

from __future__ import annotations


def _parse(text):
    from web_app import parse_import_text
    return parse_import_text(text)


# ── 旧格式回归 ──────────────────────────────────────────────


def test_simple_email_password():
    accounts = _parse("a@gmail.com----pwd1")
    assert len(accounts) == 1
    a = accounts[0]
    assert a["email"] == "a@gmail.com"
    assert a["password"] == "pwd1"
    assert "group" not in a


def test_oauth_format_no_group():
    """email----password----client_id----refresh_token (旧 OAuth 格式)。"""
    accounts = _parse(
        "u@outlook.com----pw----abc-uuid----M.C123-token-data"
    )
    assert len(accounts) == 1
    a = accounts[0]
    assert a["email"] == "u@outlook.com"
    assert a["password"] == "pw"
    assert a["client_id"] == "abc-uuid"
    assert a["refresh_token"] == "M.C123-token-data"
    assert "group" not in a


def test_multiline_split():
    accounts = _parse("a@g.com----p1\nb@g.com----p2")
    assert [a["email"] for a in accounts] == ["a@g.com", "b@g.com"]


def test_dollar_split_legacy():
    """旧的多账号一行 $$ 分隔仍然支持。"""
    accounts = _parse("a@g.com----p1$$b@g.com----p2$$c@g.com----p3")
    emails = [a["email"] for a in accounts]
    assert sorted(emails) == ["a@g.com", "b@g.com", "c@g.com"]


def test_invalid_lines_skipped():
    accounts = _parse("\n\nnot-email\na@g.com----pw\n----orphan----\n")
    assert len(accounts) == 1
    assert accounts[0]["email"] == "a@g.com"


# ── 新增：行末组名 ───────────────────────────────────────────


def test_simple_with_group_suffix():
    """email----password----组名"""
    accounts = _parse("a@g.com----pw----MyGroup")
    assert len(accounts) == 1
    assert accounts[0]["group"] == "MyGroup"
    assert "client_id" not in accounts[0]


def test_oauth_with_group_suffix():
    accounts = _parse(
        "u@outlook.com----pw----abc-uuid----M.C123-token----cursor"
    )
    assert len(accounts) == 1
    a = accounts[0]
    assert a["email"] == "u@outlook.com"
    assert a["client_id"] == "abc-uuid"
    assert a["refresh_token"] == "M.C123-token"
    assert a["group"] == "cursor"


def test_users_actual_format_with_dollar_dashdash_group():
    """完全照搬用户提供的格式：email----pwd----cid----rt$$--------group"""
    text = (
        "fkngsunza1990@outlook.com----wxcrj0329866"
        "----9e5f94bc-e8a4-4e73-b8be-63364c29d753"
        "----M.C502_BAY.0.U.-CgcO6GuvsLUocHsBUMstEPLOPVRpciOmG6XOwTiN6t4W6AlwSLIC2Tudsr4mR6x7Lea0mmpOVykntXA36R3pCUf6hlViE5k2PiDOtn38pKBGxhXGY3IGNqbBHik2yR2hg2vftnVPRA3MDDmzXyvitleb2YDWWjKampHcmR9k7EEC1huayDrJGstHOglON2ZTSArNvDzykasAye6kMq1xqh6EzSbwE7fF4hKJsvWCtEIfI9YLqtWEeFtzFgDKampCMwt0kLHzJfIcBIxqdB86r4sLcNkPfSjnZGBV4Po06mNiiLvQhfGV8lwCAm995Quxb2GcMfRHh1WnUiZNEJMsEvVwYi6V4OsNpzui4Z4Z0XRLwr6noFVw99I7kWwldEATiTe23PKLatingMI3xjvkhUkrvnHs8rmGj1ZnWulPoXlYsgdDe28e8YWGlFiUBO7g"
        "$$--------cursor\n"
        "borteykehr1993@outlook.com----eyhld1646910"
        "----9e5f94bc-e8a4-4e73-b8be-63364c29d753"
        "----M.C561-token-data-here-is-very-long-and-base64-like"
        "$$--------cursor"
    )
    accounts = _parse(text)
    assert len(accounts) == 2
    for a in accounts:
        assert a["group"] == "cursor"
        assert a["email"].endswith("@outlook.com")
        assert a["client_id"] == "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
        assert a["refresh_token"].startswith("M.C")
        assert a["password"]


def test_mixed_groups_per_row():
    """同一文本里，不同账号属于不同分组。"""
    text = (
        "a@g.com----pw1----GroupA\n"
        "b@g.com----pw2----GroupB\n"
        "c@g.com----pw3"
    )
    accounts = _parse(text)
    by_email = {a["email"]: a for a in accounts}
    assert by_email["a@g.com"]["group"] == "GroupA"
    assert by_email["b@g.com"]["group"] == "GroupB"
    assert "group" not in by_email["c@g.com"]


def test_chinese_group_name():
    """中文分组名也能正确解析。"""
    accounts = _parse("a@g.com----pw----我的分组")
    assert accounts[0]["group"] == "我的分组"


def test_group_heuristic_rejects_token():
    """看起来是 base64/URL token 的字段不会被误判为分组。"""
    # 含 = 号的不是组名
    accounts = _parse("a@g.com----pw----notgroup=eq")
    assert "group" not in accounts[0] or accounts[0].get("group") != "notgroup=eq"


def test_group_heuristic_rejects_too_long():
    """超过 64 字符的字段不当组名。"""
    long_str = "x" * 100
    accounts = _parse(f"a@g.com----pw----{long_str}")
    assert "group" not in accounts[0] or accounts[0].get("group") != long_str


def test_dollar_continuation_attaches_to_previous():
    """单独的 $$--------group 段必须挂到前一个账号上而非新建账号。"""
    accounts = _parse("a@g.com----pw1----cid----rt$$--------MyGroup")
    assert len(accounts) == 1
    assert accounts[0]["group"] == "MyGroup"


def test_multiple_accounts_each_with_dollar_group():
    """多行 + 每行结尾 $$--------group 的全场景。"""
    text = (
        "a@g.com----pw----cid1----rt1$$--------g1\n"
        "b@g.com----pw----cid2----rt2$$--------g2\n"
        "c@g.com----pw3----g3\n"
    )
    accounts = _parse(text)
    by_email = {a["email"]: a for a in accounts}
    assert by_email["a@g.com"]["group"] == "g1"
    assert by_email["b@g.com"]["group"] == "g2"
    assert by_email["c@g.com"]["group"] == "g3"


# ── 端点集成 ────────────────────────────────────────────────


def test_import_endpoint_creates_specified_group(client):
    text = "a@g.com----pw1----GroupA\nb@g.com----pw2----GroupB"
    r = client.post("/api/accounts/import", json={
        "text": text, "group": "默认分组", "skip_duplicate": False,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["success"] == 2
    assert sorted(body["groups_created"]) == ["GroupA", "GroupB"]

    groups = [g["name"] for g in client.get("/api/groups").json()]
    assert "GroupA" in groups and "GroupB" in groups

    a_accs = client.get("/api/accounts?group=GroupA").json()
    b_accs = client.get("/api/accounts?group=GroupB").json()
    assert {x["email"] for x in a_accs} == {"a@g.com"}
    assert {x["email"] for x in b_accs} == {"b@g.com"}


def test_import_endpoint_per_account_group_overrides_form(client):
    """单条自带组名优先于表单的 group。"""
    text = "a@g.com----pw1----RowGroup\nb@g.com----pw2"
    r = client.post("/api/accounts/import", json={
        "text": text, "group": "FormGroup", "skip_duplicate": False,
    })
    assert r.status_code == 200
    accs = {a["email"]: a for a in client.get("/api/accounts").json()}
    assert accs["a@g.com"]["group"] == "RowGroup"
    assert accs["b@g.com"]["group"] == "FormGroup"


def test_import_users_actual_format_creates_cursor_group(client):
    """端到端验证：用户的真实格式提交后，cursor 分组被创建且账号正确归类。"""
    text = (
        "fkngsunza1990@outlook.com----pw1"
        "----9e5f94bc-e8a4-4e73-b8be-63364c29d753"
        "----M.C502-rt-data$$--------cursor\n"
        "borteykehr1993@outlook.com----pw2"
        "----9e5f94bc-e8a4-4e73-b8be-63364c29d753"
        "----M.C561-rt-data$$--------cursor"
    )
    r = client.post("/api/accounts/import", json={
        "text": text, "group": "默认分组", "skip_duplicate": False,
    })
    body = r.json()
    assert body["success"] == 2
    assert "cursor" in body["groups_created"]

    cursor_accs = client.get("/api/accounts?group=cursor").json()
    assert len(cursor_accs) == 2
    for a in cursor_accs:
        assert a["type"] == "OAuth2"
        assert a["client_id"] == "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
