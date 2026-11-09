import fs from "node:fs";
import vm from "node:vm";
import assert from "node:assert/strict";

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.dataset = {};
    this.attributes = {};
    this.listeners = {};
    this.disabled = false;
    this._text = null;
  }
  append(...nodes) { this._text = null; this.children.push(...nodes); }
  replaceChildren(...nodes) { this._text = null; this.children = nodes; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  addEventListener(name, handler) { this.listeners[name] = handler; }
  querySelector() { return null; }
  querySelectorAll(selector) {
    return descend(this).filter((n) => selector === "input[data-select-user]" && n instanceof Input && n.dataset.selectUser);
  }
  set textContent(value) { this.children = []; this._text = String(value); }
  get textContent() { return this._text ?? this.children.map((c) => c.textContent).join(""); }
}
class Input extends Element {}
class Button extends Element {}
class Select extends Element {}
class Form extends Element {}
const descend = (node) => node.children.flatMap((n) => [n, ...descend(n)]);
const create = (tag) => new ({ input: Input, button: Button, select: Select, form: Form }[tag] ?? Element)(tag);
const users = create("tbody"), summary = create("p"), audit = create("div"), filter = create("form");
const bulk = create("form"), type = create("select"), submit = create("button"), count = create("span"), all = create("input"), notice = create("p");
bulk.append(type, submit, count);
const nodes = new Map([
  ["[data-users]", users], ["[data-summary]", summary], ["[data-audit]", audit],
  ["[data-filter-form]", filter], ["[data-bulk-type-form]", bulk], ["[data-bulk-type]", type],
  ["[data-bulk-submit]", submit], ["[data-selected-count]", count], ["[data-select-all]", all], ["[data-notice]", notice]
]);
const sessionMode = process.argv.includes("--session");
const storage = new Map();
const redirects = [];
let removedToken = false, expired = false;
const calls = [];
let approved = false, rejected = false, release = null, hold = false;
const context = vm.createContext({
  document: {
    createElement: create,
    querySelector(selector) {
      if (selector === "meta[name='admin-api-base']") return { getAttribute: () => sessionMode ? "/oauth2/admin/api" : "/manage-api" };
      if (selector === "meta[name='admin-auth-mode']" && sessionMode) return { getAttribute: () => "session" };
      if (selector === "meta[name='admin-session-csrf']" && sessionMode) return { getAttribute: () => "synthetic-csrf" };
      return nodes.get(selector) ?? null;
    },
    querySelectorAll() {
      return [...new Set([...nodes.values()].flatMap((n) => [n, ...descend(n)]))]
        .filter((n) => n instanceof Input || n instanceof Button || n instanceof Select);
    }
  },
  HTMLElement: Element, HTMLInputElement: Input, HTMLButtonElement: Button,
  HTMLSelectElement: Select, HTMLFormElement: Form,
  FormData: class { get() { return null; } }, URLSearchParams, Intl, Date, Error,
  fetch: async (path, options = {}) => {
    calls.push({ path, options });
    if (options.method === "PATCH") {
      if (hold) await new Promise((resolve) => { release = resolve; });
      return { ok: !rejected, text: async () => JSON.stringify(rejected ? { error: { message: "Admin protected" } } : { changedCount: 2, unchangedCount: 0 }) };
    }
    if (expired) return { ok: false, status: 401, text: async () => JSON.stringify({ error: { message: "Expired" } }) };
    return { ok: true, status: 200, text: async () => JSON.stringify(context.payload) };
  },
  window: { location: { assign: (path) => redirects.push(path) }, confirm: () => approved, setTimeout() {}, sessionStorage: {
    getItem: (key) => { if (sessionMode) throw new Error("Session mode must never read a bearer token"); return storage.get(key) ?? null; },
    setItem: (key, value) => storage.set(key, value),
    removeItem: (key) => { removedToken = true; storage.delete(key); }
  } }
});
new vm.Script(fs.readFileSync(process.argv[2], "utf8")).runInContext(context);
const poison = '<img src=x onerror="globalThis.pwned=1">';
context.payload = { total: 2, items: ["a", "b"].map((id) => ({ id, email: poison, name: poison,
  status: "ACTIVE", userType: "CUSTOMER", roles: [{id:"r", serviceKey:poison,name:poison}], createdAt: "2026-11-03T00:00:00Z" })) };
const render = () => new vm.Script("renderUsers(payload)").runInContext(context);
const boxes = () => users.querySelectorAll("input[data-select-user]");
const tick = () => new Promise((resolve) => setImmediate(resolve));
const chooseAll = () => { all.checked = true; all.listeners.change({ target: all }); };
const send = () => bulk.listeners.submit({ preventDefault() {} });
await tick(); await tick();
render();
assert.equal(submit.disabled, true);
assert.equal(boxes().length, 2);
boxes()[0].checked = true;
users.listeners.change({ target: boxes()[0] });
assert.equal(count.textContent, "선택 1명");
assert.equal(all.indeterminate, true);
chooseAll();
assert.equal(count.textContent, "선택 2명");
assert.equal(all.checked, true);
assert.equal(submit.disabled, false);
type.value = "EMPLOYEE";
send();
assert.equal(calls.filter((x) => x.options.method === "PATCH").length, 0); // Cancel is inert.
storage.set("wise_sso_admin_access_token", "synthetic-test-token");
approved = true;
hold = true;
send();
await tick();
assert.equal(submit.disabled, true);
assert.equal(all.disabled, true);
const request = calls.find((x) => x.options.method === "PATCH");
assert.equal(request.path, (sessionMode ? "/oauth2/admin/api" : "/manage-api") + "/users/type");
assert.equal(request.options.credentials, "same-origin");
if (sessionMode) {
  assert.equal(request.options.headers.authorization, undefined);
  assert.equal(request.options.headers["x-admin-csrf"], "synthetic-csrf");
  assert.equal(removedToken, true);
}
assert.deepEqual(JSON.parse(request.options.body), { userIds: ["a", "b"], userType: "EMPLOYEE", reasonCode: "ADMIN_DASHBOARD_BULK_USER_TYPE_CHANGE" });
boxes()[0].checked = false;
users.listeners.change({ target: boxes()[0] });
assert.equal(count.textContent, "선택 2명"); // In-flight input cannot change the target set.
release();
await tick(); await tick();
assert.equal(count.textContent, "선택 0명");
assert.equal(submit.disabled, true);
assert.match(notice.textContent, /2명 변경/);
assert.equal(descend(users).some((n) => ["IMG", "SCRIPT", "SVG", "IFRAME"].includes(n.tagName)), false);
assert.equal(context.pwned, undefined);
chooseAll();
filter.listeners.input();
assert.equal(count.textContent, "선택 0명"); // A changed filter clears stale selections.
assert.equal(all.checked, false);
chooseAll();
rejected = true; hold = false;
send();
await tick(); await tick();
assert.equal(count.textContent, "선택 2명");
assert.equal(submit.disabled, false);
assert.equal(notice.textContent, "Admin protected");
context.payload = { total: 0, items: [] };
render();
assert.equal(count.textContent, "선택 0명");
assert.equal(all.disabled, true);
assert.equal(submit.disabled, true);
assert.equal(users.children[0].children[0].colSpan, 7);
if (sessionMode) {
  expired = true;
  await new vm.Script("apiFetch('/users').catch(() => {})").runInContext(context);
  assert.deepEqual(redirects, ["/oauth2/admin/login?reauth=1"]);
}
process.stdout.write(JSON.stringify({ selection: true, cancellation: true, busyGuard: true, batchRequest: true,
  refreshReset: true, filterReset: true, failureRetention: true, emptyState: true, safeText: true }));
