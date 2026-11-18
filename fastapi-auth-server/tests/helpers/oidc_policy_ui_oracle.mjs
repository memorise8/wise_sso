import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const mode = process.argv[3];
const memberMode = mode.startsWith("members-");
const calls = [];
const listeners = new Map();
const walk = (node) => [node, ...node.children.flatMap(walk)];

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.events = {};
    this.dataset = {};
    this.style = {};
    this.disabled = false;
    this.hidden = false;
    this.value = "";
    this._text = "";
    this.attributes = {};
  }
  set textContent(value) {
    this._text = String(value);
    this.children = [];
  }
  get textContent() {
    return this._text + this.children.map((child) => child.textContent).join("");
  }
  set innerHTML(value) {
    throw new Error("금지된 HTML 삽입이 실행됐습니다.");
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) {
    this._text = "";
    this.children = [...nodes];
  }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  addEventListener(key, callback) {
    (this.events[key] ??= []).push(callback);
  }
  fire(key) {
    if (key === "click" && this.disabled) return;
    for (const callback of this.events[key] ?? []) {
      callback({ preventDefault() {} });
    }
  }
  querySelector(key) { return fields.get(key) ?? null; }
  querySelectorAll(key) {
    return walk(this).filter((child) => child.tagName === key.toUpperCase());
  }
}

const panel = new Element("section");
const fields = new Map();
for (const key of ["tabs", "note", "policy", "count", "members", "pager", "add"]) {
  fields.set(
    `[data-service-${key}]`,
    new Element(key === "add" ? "form" : "div")
  );
}
fields.set("select[name='role']", new Element("select"));

class CustomEvent {
  constructor(type, options = {}) {
    this.type = type;
    this.detail = options.detail;
  }
}

const document = {
  createElement: (tag) => new Element(tag),
  querySelector(key) {
    if (key === "[data-service-panel]") return panel;
    const meta = {
      "meta[name='admin-auth-mode']": "session",
      "meta[name='admin-access']": mode === "viewer" ? "viewer" : "admin",
      "meta[name='admin-api-base']": "/oauth2/admin/api",
      "meta[name='admin-session-csrf']": "synthetic-csrf",
    };
    return key in meta ? { getAttribute: () => meta[key] } : null;
  },
  addEventListener(type, callback) {
    if (!listeners.has(type)) listeners.set(type, []);
    listeners.get(type).push(callback);
  },
  dispatchEvent(event) {
    for (const callback of listeners.get(event.type) ?? []) callback(event);
  },
};

const malicious = '<img src=x onerror="globalThis.policyXss=1">';
const policy = {
  allowedUserTypes: ["EMPLOYEE"],
  requiredRoles: [{ serviceKey: "gitlab", name: "user" }],
  groupsServiceKeys: ["gitlab"],
  allowWithoutRequiredRole: false,
  ssoAutoLogin: false,
};
const versions = { "service-a": 2, "service-b": 7 };
const histories = {};

function historyFor(client) {
  return histories[client] ??= ["own", "other", "done"].map((kind) => ({
    id: `${client}-${kind}`,
    status: kind === "done" ? "APPLIED" : "PENDING",
    requestedById: kind === "own" ? "admin-self" : "admin-other",
    requestedByEmail: `${kind}@${client}.invalid`,
    requestedAt: "2026-11-18T00:15:05Z",
    reasonCode: malicious,
    resolvedAt: null,
    baseVersion: versions[client],
    beforePolicy: policy,
    proposedPolicy: policy,
  }));
}

const response = (payload, status = 200) => ({
  ok: status < 400,
  status,
  json: async () => payload,
  text: async () => JSON.stringify(payload),
});

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

const delayed = new Map();
const memberLoads = new Map();

async function fetch(path, options = {}) {
  const url = new URL(path, "https://example.invalid");
  const method = options.method ?? "GET";
  const body = options.body ? JSON.parse(options.body) : null;
  calls.push({ path: url.pathname, method, body, headers: options.headers });

  if (url.pathname === "/oauth2/admin/api/clients") {
    if (!memberMode) return response({ items: [] });
    return response({ items: ["service-a", "service-b"].map((clientId) => ({
      clientId, requiredRoles: policy.requiredRoles,
      allowedUserTypes: clientId === "service-a" ? ["CUSTOMER"] : ["EMPLOYEE"],
      allowWithoutRequiredRole: clientId === "service-a",
      ssoAutoLogin: false, eligibleCount: 1
    })) });
  }
  const match = url.pathname.match(/\/clients\/([^/]+)\/(.*)/);
  assert.ok(match, "예상하지 못한 API 요청입니다.");
  const [, client, suffix] = match;
  let payload;

  if (suffix === "members") {
    memberLoads.set(client, (memberLoads.get(client) ?? 0) + 1);
    payload = { items: [{
      id: `${client}-user`, name: `${client}-user`,
      email: `${client}-user@example.invalid`, userType: "CUSTOMER",
      requiredRoleMatched: client !== "service-a", matchedRoles: []
    }], total: 1, page: 1, pageSize: 25 };
    if (mode.startsWith("members-late-") && client === "service-a"
        && memberLoads.get(client) > 1) {
      const pending = deferred();
      delayed.set("members", { ...pending, payload });
      return pending.promise;
    }
  } else if (suffix === "policy") {
    payload = {
      clientId: client,
      version: versions[client],
      policy,
      actorUserId: "admin-self",
      updatedAt: "2026-11-18T00:15:05Z",
    };
  } else if (suffix === "policy-changes") {
    payload = {
      items: structuredClone(historyFor(client)),
      page: 1, pageSize: 25, hasMore: false,
    };
  } else if (suffix.endsWith("/decision")) {
    assert.equal(method, "POST");
    const item = historyFor(client).find((item) => suffix.includes(item.id));
    assert.ok(item);
    item.status = body.decision === "APPROVE" ? "APPLIED" : "REJECTED";
    if (body.decision === "APPROVE") versions[client] += 1;
    payload = item;
  } else {
    payload = {
      decision: {
        decision: "APPROVE",
        decidedByEmail: "approver@example.invalid",
        decidedAt: "2026-11-18T00:15:05Z",
        reasonCode: malicious,
      },
    };
  }

  if (
    mode.startsWith("stale-") && client === "service-a" &&
    ["policy", "policy-changes"].includes(suffix)
  ) {
    const pending = deferred();
    delayed.set(suffix, { ...pending, payload });
    return pending.promise;
  }
  return response(payload);
}

const context = vm.createContext({
  document, fetch, Intl, Date, Error, URLSearchParams, CustomEvent,
  window: {
    CustomEvent,
    prompt: () => "정책 검토",
    location: { assign() {} },
  },
});
new vm.Script(fs.readFileSync(process.argv[2], "utf8")).runInContext(context);

async function settle() {
  for (let index = 0; index < 20; index += 1) {
    await new Promise(setImmediate);
  }
}
const select = (clientId) => document.dispatchEvent(
  new CustomEvent("admin-service-selected", { detail: { clientId } })
);

await settle();

if (memberMode) {
  const tabs = fields.get("[data-service-tabs]");
  const members = fields.get("[data-service-members]");
  const count = fields.get("[data-service-count]");
  const note = fields.get("[data-service-note]");
  const summary = fields.get("[data-service-policy]");
  const tab = (id) => tabs.children.find((item) => item.dataset.clientId === id);
  assert.ok(tab("service-a"));
  assert.ok(tab("service-b"));
  assert.ok(members.textContent.includes("service-a-user"));
  if (mode === "members-policy") {
    assert.ok(note.textContent.includes("고객"));
    assert.ok(note.textContent.includes("필요 역할이 없어도"));
    assert.ok(note.textContent.includes("서비스 내부 권한"));
    assert.ok(!note.textContent.includes("누구나"));
    assert.ok(!summary.textContent.includes("서비스가 초대로 거름"));
    assert.ok(members.textContent.includes("역할 없음 · SSO 로그인 허용"));
    tab("service-b").fire("click");
    await settle();
    assert.ok(note.textContent.includes("직원"));
    assert.ok(note.textContent.includes("필요 역할 조건을 충족"));
    assert.ok(!note.textContent.includes("필요 역할이 없어도"));
  } else {
    tab("service-a").fire("click");
    tab("service-b").fire("click");
    await settle();
    assert.ok(
      calls.some((call) => call.path.endsWith("/service-b/members")),
      "이전 조회 중 새 탭 조회가 생략됐습니다."
    );
    assert.ok(members.textContent.includes("service-b-user"));
    const expectedMembers = members.textContent;
    const expectedCount = count.textContent;
    const previous = delayed.get("members");
    assert.ok(previous);
    if (mode === "members-late-error") {
      previous.reject(new Error("지난 구성원 조회 실패"));
    } else {
      previous.resolve(response(previous.payload));
    }
    await settle();
    assert.equal(members.textContent, expectedMembers);
    assert.equal(count.textContent, expectedCount);
    assert.ok(!members.textContent.includes("service-a-user"));
  }
  assert.ok(calls.every((call) => call.method === "GET"));
} else if (mode === "viewer") {
  select("service-a");
  await settle();
  assert.equal(panel.children.length, 0);
  assert.ok(calls.every((call) => call.path === "/oauth2/admin/api/clients"));
} else {
  select("service-a");
  if (mode.startsWith("stale-")) {
    select("service-b");
    await settle();
    const root = panel.children[0];
    const expected = root.textContent;
    assert.ok(expected.includes("done@service-b.invalid"));

    const oldHistory = delayed.get("policy-changes");
    oldHistory.resolve(response(oldHistory.payload));
    const oldPolicy = delayed.get("policy");
    if (mode === "stale-error") {
      oldPolicy.reject(new Error("지난 서비스 조회 실패"));
    } else {
      oldPolicy.resolve(response(oldPolicy.payload));
    }
    await settle();
    assert.equal(
      root.textContent, expected,
      "이전 서비스의 늦은 응답이 현재 화면을 바꿨습니다."
    );
    assert.equal(root.hidden, false);
  } else {
    await settle();
    const root = panel.children[0];
    const cards = () => walk(root).filter((node) => node.tagName === "ARTICLE");
    const findButton = (card, label) => walk(card).find(
      (node) => node.tagName === "BUTTON" && node.textContent === label
    );
    assert.equal(cards().length, 3);

    if (mode === "record") {
      const card = cards()[2];
      findButton(card, "승인·거절 기록 보기").fire("click");
      await settle();
      const detail = walk(card).find(
        (node) => "policyDecision" in node.dataset
      );
      assert.equal(detail.hidden, false);
      assert.ok(detail.textContent.includes("approver@example.invalid"));
      assert.ok(detail.textContent.includes("2026-11-18 09:15:05 (KST)"));
      assert.ok(detail.textContent.includes(malicious));
      assert.equal(root.children[1].textContent, "");
      assert.ok(cards().slice(0, 2).every(
        (other) => !other.textContent.includes("approver@example.invalid")
      ));
    } else if (mode === "self") {
      for (const label of ["승인", "거절"]) {
        const control = findButton(cards()[0], label);
        assert.equal(control.disabled, true);
        control.fire("click");
      }
      await settle();
      assert.ok(calls.every((call) => call.method === "GET"));
    } else {
      assert.ok(["approve", "reject"].includes(mode));
      const control = findButton(
        cards()[1], mode === "approve" ? "승인" : "거절"
      );
      assert.equal(control.disabled, false);
      control.fire("click");
      await settle();
      const posts = calls.filter((call) => call.method === "POST");
      assert.equal(posts.length, 1);
      assert.equal(
        posts[0].path,
        "/oauth2/admin/api/clients/service-a/policy-changes/service-a-other/decision"
      );
      assert.equal(
        posts[0].body.decision, mode === "approve" ? "APPROVE" : "REJECT"
      );
      assert.equal(posts[0].body.reasonCode, "정책 검토");
      assert.equal(posts[0].headers["x-admin-csrf"], "synthetic-csrf");
    }

    assert.ok(!walk(root).some((node) =>
      ["IMG", "SCRIPT", "IFRAME", "SVG"].includes(node.tagName)
    ));
    assert.equal(context.policyXss, undefined);
  }
}
process.stdout.write(JSON.stringify({ mode, passed: true }));
