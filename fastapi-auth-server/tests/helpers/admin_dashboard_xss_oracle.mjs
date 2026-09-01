import fs from "node:fs";
import vm from "node:vm";

class Element {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.className = "";
    this.dataset = {};
    this.hidden = false;
    this._text = null;
  }

  append(...children) {
    this._text = null;
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this._text = null;
    this.children = [...children];
  }

  addEventListener() {}

  querySelector() {
    return null;
  }

  set textContent(value) {
    this.children = [];
    this._text = String(value);
  }

  get textContent() {
    return this._text ?? this.children.map((child) => child.textContent).join("");
  }
}

class HTMLButtonElement extends Element {}
class HTMLInputElement extends Element {}
class HTMLSelectElement extends Element {}
class HTMLFormElement extends Element {}

const users = new Element("tbody");
const audit = new Element("section");
const summary = new Element("span");
const elements = new Map([
  ["[data-users]", users],
  ["[data-audit]", audit],
  ["[data-summary]", summary]
]);

const document = {
  createElement(tagName) {
    if (tagName === "button") return new HTMLButtonElement(tagName);
    if (tagName === "input") return new HTMLInputElement(tagName);
    if (tagName === "select") return new HTMLSelectElement(tagName);
    if (tagName === "form") return new HTMLFormElement(tagName);
    return new Element(tagName);
  },
  querySelector(selector) {
    if (selector === "meta[name='admin-api-base']") {
      return { getAttribute: () => "/manage-api" };
    }
    return elements.get(selector) ?? null;
  },
  querySelectorAll() {
    return [];
  }
};

const sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const context = vm.createContext({
  console,
  document,
  Element,
  HTMLElement: Element,
  HTMLButtonElement,
  HTMLInputElement,
  HTMLSelectElement,
  HTMLFormElement,
  FormData,
  URLSearchParams,
  Intl,
  Date,
  Error,
  fetch: async () => ({ ok: true, text: async () => "" }),
  window: { sessionStorage, setTimeout() {} }
});

const source = fs.readFileSync(process.argv[2], "utf8");
new vm.Script(source, { filename: process.argv[2] }).runInContext(context);

context.payload = {
  userPage: {
    total: 1,
    items: [{
      id: '<img src=x onerror="globalThis.userIdXss=1">',
      email: '<svg onload="globalThis.emailXss=1">',
      name: '<script>globalThis.nameXss=1</script>',
      status: "ACTIVE",
      createdAt: "2026-07-29T00:00:00.000Z",
      roles: [{
        id: '<iframe srcdoc="<script>globalThis.roleIdXss=1</script>">',
        serviceKey: '<math href="javascript:globalThis.roleServiceXss=1">',
        name: '<img src=x onerror="globalThis.roleNameXss=1">'
      }]
    }]
  },
  auditPage: {
    items: [
      {
        eventType: '<img src=x onerror="globalThis.eventXss=1">',
        outcome: '<svg onload="globalThis.outcomeXss=1">',
        reasonCode: '<script>globalThis.reasonXss=1</script>',
        userId: '<iframe src="javascript:globalThis.auditUserXss=1">',
        targetUserId: null,
        createdAt: "2026-07-29T00:00:00.000Z"
      },
      {
        eventType: "admin_user_status_changed",
        outcome: "SUCCESS",
        reasonCode: null,
        userId: null,
        targetUserId: '<img src=x onerror="globalThis.targetXss=1">',
        createdAt: "2026-07-29T00:00:00.000Z"
      }
    ]
  }
};
new vm.Script("renderUsers(payload.userPage); renderAudit(payload.auditPage);").runInContext(context);

const snapshot = (root) => {
  const tags = [];
  const texts = [];
  const datasets = [];
  const visit = (node) => {
    tags.push(node.tagName);
    if (node._text !== null) texts.push(node._text);
    datasets.push({ ...node.dataset });
    node.children.forEach(visit);
  };
  visit(root);
  return { tags, texts, datasets };
};

process.stdout.write(JSON.stringify({
  users: snapshot(users),
  audit: snapshot(audit),
  executedGlobals: Object.keys(context).filter((key) => key.endsWith("Xss"))
}));
