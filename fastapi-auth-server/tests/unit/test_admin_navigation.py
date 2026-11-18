"""사용자 메뉴 복귀와 상세 화면의 목록 링크를 검증합니다."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]

SCRIPT = r"""
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Element {
  constructor(text = "") {
    this.textContent = text;
    this.dataset = {};
    this.attributes = {};
    this.events = {};
  }
  setAttribute(key, value) { this.attributes[key] = value; }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(key, callback) { this.events[key] = callback; }
}
const shell = new Element();
const title = new Element();
const users = new Element("사용자");
users.dataset.nav = "users";
const audit = new Element("감사 로그");
audit.dataset.nav = "audit";
const history = [];
const document = {
  querySelector(selector) {
    if (selector === ".admin-shell") return shell;
    if (selector === "[data-page-title]") return title;
    return null;
  },
  querySelectorAll(selector) {
    return selector === "[data-nav]" ? [users, audit] : [];
  },
  addEventListener() {},
};
const context = vm.createContext({
  document,
  HTMLElement: Element,
  window: {
    location: { hash: "#audit", pathname: process.argv[2], search: "" },
    history: { replaceState: (...args) => history.push(args) },
  },
  fetch() { throw new Error("메뉴 이동에서 불필요한 API 요청이 발생했습니다."); },
});
new vm.Script(fs.readFileSync(process.argv[1], "utf8")).runInContext(context);
assert.equal(shell.dataset.currentView, "audit");
users.events.click();
assert.equal(shell.dataset.currentView, "users");
assert.equal(title.textContent, "사용자");
assert.equal(users.attributes["aria-current"], "page");
assert.equal(audit.attributes["aria-current"], undefined);
assert.equal(history.length, 1);
assert.equal(history[0][2], "#users");
"""


@pytest.mark.parametrize("path", ["/oauth2/admin/dashboard", "/manage/dashboard"])
def test_users_navigation_without_reload(path: str) -> None:
    node = shutil.which("node")
    assert node is not None, "화면 이동 검사에는 Node.js가 필요합니다."
    result = subprocess.run(  # noqa: S603
        [
            node,
            "--input-type=module",
            "-e",
            SCRIPT,
            str(ROOT / "src/wiseacct_sso/static/assets/admin-shell.js"),
            path,
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "relative",
    [
        "src/wiseacct_sso/static/admin-dashboard.html",
        "../auth-server/public/admin-dashboard.html",
        "src/wiseacct_sso/static/admin-user-detail.html",
    ],
)
def test_navigation_has_no_duplicate_dashboard_menu(relative: str) -> None:
    source = (ROOT / relative).read_text(encoding="utf-8")
    assert "data-dashboard-home" not in source
    if relative.endswith("admin-user-detail.html"):
        assert 'href="/oauth2/admin/dashboard#users"' in source
        assert "← 사용자 목록" in source
    else:
        assert 'data-nav="users"' in source
