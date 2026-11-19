import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.dataset = {};
    this.events = {};
    this.disabled = false;
    this.hidden = false;
    this.value = "";
    this._text = "";
  }
  set textContent(value) {
    this.children = [];
    this._text = String(value);
  }
  get textContent() {
    return this._text + this.children.map((child) => child.textContent).join("");
  }
  set innerHTML(value) {
    throw new Error("금지된 HTML 삽입이 실행됐습니다.");
  }
  append(...nodes) {
    this.children.push(...nodes);
  }
  replaceChildren(...nodes) {
    this._text = "";
    this.children = [...nodes];
  }
  addEventListener(name, callback) {
    (this.events[name] ??= []).push(callback);
  }
  fire(name) {
    for (const callback of this.events[name] ?? []) callback({ preventDefault() {} });
  }
  remove() {
    this.removed = true;
  }
  reset() {}
  querySelector(selector) {
    return nodes.get(selector) ?? null;
  }
  querySelectorAll() {
    return walk(this).filter((node) =>
      ["BUTTON", "INPUT", "SELECT"].includes(node.tagName));
  }
  createTHead() {
    const head = new Element("thead");
    this.append(head);
    return head;
  }
  createTBody() {
    const body = new Element("tbody");
    this.append(body);
    return body;
  }
  insertRow() {
    const row = new Element("tr");
    this.append(row);
    return row;
  }
}
function walk(node) {
  return [node, ...node.children.flatMap(walk)];
}
async function settle() {
  for (let index = 0; index < 40; index += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

const mode = process.argv[3];
const viewer = mode === "viewer";
const nodes = new Map();
for (const [name, tag] of [
  ["panel", "section"], ["start", "form"], ["status", "p"],
  ["list", "ul"], ["list-pager", "div"], ["detail", "section"],
  ["title", "h3"], ["metadata", "p"], ["counts", "p"],
  ["filter", "select"], ["items", "div"], ["item-pager", "div"],
  ["complete", "button"], ["refresh", "button"],
]) {
  nodes.set(`[data-review-${name}]`, new Element(tag));
}
const panel = nodes.get("[data-review-panel]");
const nav = new Element("button");
const form = nodes.get("[data-review-start]");
const complete = nodes.get("[data-review-complete]");
const filter = nodes.get("[data-review-filter]");
panel.append(...[...nodes.values()].filter((node) => node !== panel));
filter.value = "";
complete.dataset.reviewBlocked = "true";

const malicious = '<img src=x onerror="globalThis.reviewXss=1">';
form.values = {
  title: malicious, serviceKeys: "sso,gitlab", reasonCode: "정기 점검",
};
form.fields = Object.entries(form.values).map(([name, value]) => {
  const field = new Element("input");
  field.name = name;
  field.value = value;
  form.append(field);
  return field;
});

const review = {
  id: "review-id", title: malicious, status: "OPEN",
  startedById: "admin-id", startedByEmail: "admin@example.invalid", startedAt: "2026-11-17T00:00:00+00:00",
  total: 1, counts: { PENDING: 1, KEEP: 0, REVOKE: 0, ALREADY_REMOVED: 0 },
};
const item = {
  id: "item-id", userId: "target-id", userName: malicious,
  userEmail: "synthetic@example.invalid", userType: "EMPLOYEE",
  userStatus: "ACTIVE", serviceKey: "gitlab", roleName: "user",
  decision: "PENDING", decidedById: null, decidedAt: null, reasonCode: null,
};
const calls = [];
let confirmations = 0;
let prompts = 0;
const document = {
  createElement: (tag) => new Element(tag),
  querySelector(selector) {
    if (selector === '[data-nav="reviews"]') return nav;
    if (selector === 'meta[name="admin-access"]') {
      return { content: viewer ? "viewer" : "admin" };
    }
    if (selector === 'meta[name="admin-session-csrf"]') return { content: "synthetic-csrf" };
    return nodes.get(selector) ?? null;
  },
};

const context = vm.createContext({
  document, Intl, Date, Error, URLSearchParams,
  FormData: class {
    constructor(target) {
      this.values = Object.fromEntries(
        target.fields.filter((field) => !field.disabled)
          .map((field) => [field.name, field.value])
      );
    }
    get(key) { return this.values[key] ?? ""; }
  },
  location: { hash: "", assign() {} },
  window: {
    prompt: () => { prompts += 1; return "점검 확인"; },
    confirm: () => { confirmations += 1; return true; },
  },
  fetch: async (path, options) => {
    const url = new URL(path, "https://example.invalid");
    const suffix = url.pathname.replace("/oauth2/admin/api/access-reviews", "");
    const method = options.method ?? "GET";
    const body = options.body ? JSON.parse(options.body) : null;
    calls.push({ suffix, method, body, headers: options.headers });
    let payload;
    if (suffix === "" && method === "POST") {
      payload = review;
    } else if (suffix === "") {
      payload = { items: [review], page: 1, pageSize: 25, hasMore: false };
    } else if (suffix === "/review-id/items") {
      const selected = url.searchParams.get("decision");
      payload = {
        items: !selected || selected === item.decision ? [item] : [],
        page: 1, pageSize: 25, hasMore: false,
      };
    } else if (suffix.endsWith("/decision")) {
      item.decision = mode === "conflict" ? "KEEP" : body.decision;
      item.decidedById = "admin-id";
      item.decidedByEmail = "admin@example.invalid";
      item.decidedAt = "2026-11-17T00:01:00+00:00";
      item.reasonCode = body.reasonCode ?? "권한 유지(변경 없음)";
      review.counts.PENDING = 0;
      review.counts[item.decision] = 1;
      if (mode === "conflict") {
        return {
          ok: false, status: 409,
          json: async () => ({ error: { code: "ACCESS_REVIEW_ITEM_DECIDED" } }),
        };
      }
      payload = { decision: item.decision };
    } else if (suffix.endsWith("/complete")) {
      review.status = "COMPLETED";
      review.completedById = mode === "different-completer" ? "other-admin-id" : "admin-id";
      review.completedByEmail = mode === "different-completer"
        ? "other@example.invalid" : "admin@example.invalid";
      review.completedAt = "2026-11-17T00:02:00+00:00";
      payload = review;
    } else {
      payload = review;
    }
    return { ok: true, status: method === "POST" && suffix === "" ? 201 : 200, json: async () => payload };
  },
});

new vm.Script(fs.readFileSync(process.argv[2], "utf8")).runInContext(context);

if (viewer) {
  assert.equal(panel.removed, true);
  assert.equal(nav.removed, true);
  assert.equal(calls.length, 0);
} else {
  form.fire("submit");
  await settle();
  const start = calls.find((call) => call.method === "POST" && call.suffix === "");
  assert.deepEqual(start.body.serviceKeys, ["sso", "gitlab"]);
  assert.equal(start.body.title, malicious);
  assert.equal(start.body.reasonCode, "정기 점검");
  assert.equal(start.headers["x-admin-csrf"], "synthetic-csrf");

  assert.equal(filter.value, "");
  const metadata = nodes.get("[data-review-metadata]").textContent;
  assert.match(metadata, /2026-11-17 09:00:00 \(KST\)/);
  assert.match(metadata, /\(KST\)/);
  assert.ok(metadata.includes("admin@example.invalid"));
  assert.ok(!metadata.includes("admin-id"));
  assert.equal(complete.disabled, true);

  const label = mode === "KEEP" ? "유지" : "회수";
  const action = walk(nodes.get("[data-review-items]")).find(
    (node) => node.tagName === "BUTTON" && node.textContent === label
  );
  assert.ok(action);
  action.fire("click");
  await settle();

  const decisions = calls.filter((call) => call.suffix.endsWith("/decision"));
  assert.equal(decisions.length, 1);
  assert.equal(decisions[0].body.reasonCode, mode === "KEEP" ? undefined : "점검 확인");
  assert.equal(prompts, mode === "KEEP" ? 0 : 1);
  assert.equal(decisions[0].headers["x-admin-csrf"], "synthetic-csrf");
  assert.equal(confirmations, mode === "KEEP" ? 0 : 1);
  assert.equal(complete.disabled, false);

  if (mode === "conflict") {
    assert.match(nodes.get("[data-review-status]").textContent, /이미 결정/);
  } else {
    assert.equal(item.decision, mode === "KEEP" ? "KEEP" : "REVOKE");
    complete.fire("click");
    await settle();
    assert.equal(review.status, "COMPLETED");
    const completedMetadata = nodes.get("[data-review-metadata]").textContent;
    assert.equal(completedMetadata.split("admin@example.invalid").length - 1, 1);
    if (mode === "different-completer") {
      assert.ok(completedMetadata.includes("other@example.invalid"));
    }
    assert.equal(complete.disabled, true);
    assert.equal(calls.filter((call) => call.suffix.endsWith("/complete")).length, 1);
  }

  assert.ok(walk(panel).some((node) => node.textContent.includes(malicious)));
  assert.ok(!walk(panel).some((node) =>
    ["IMG", "SCRIPT", "SVG", "IFRAME"].includes(node.tagName)));
  assert.equal(context.reviewXss, undefined);
}
process.stdout.write(JSON.stringify({ mode, passed: true }));
