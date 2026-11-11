(() => {
  // Layout only: which panel is on screen, the user-type tabs, and where the session box sits.
  const shell = document.querySelector(".admin-shell");
  const title = document.querySelector("[data-page-title]");
  const navItems = [...document.querySelectorAll("[data-nav]")];
  const views = new Set(navItems.map((item) => item.dataset.nav));
  if (!(shell instanceof HTMLElement) || !navItems.length) return;

  const session = document.querySelector("[data-session-panel]");
  const slot = document.querySelector("[data-account-slot]");
  if (session && slot) slot.append(session);

  const show = (view) => {
    const current = views.has(view) ? view : "users";
    shell.dataset.currentView = current;
    for (const item of navItems) {
      if (item.dataset.nav === current) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    }
    if (title) title.textContent = navItems.find((item) => item.dataset.nav === current)?.textContent ?? "사용자";
  };

  for (const item of navItems) {
    item.addEventListener("click", () => {
      window.history.replaceState(null, "", `#${item.dataset.nav}`);
      show(item.dataset.nav);
    });
  }
  show(window.location.hash.slice(1));

  const filter = document.querySelector("[data-filter-form]");
  const typeSelect = filter?.querySelector("select[name='userType']");
  const tabs = [...document.querySelectorAll("[data-type-tab]")];
  for (const tab of tabs) {
    tab.addEventListener("click", () => {
      if (!(filter instanceof HTMLFormElement) || !(typeSelect instanceof HTMLSelectElement)) return;
      typeSelect.value = tab.dataset.typeTab ?? "";
      for (const other of tabs) other.setAttribute("aria-selected", String(other === tab));
      filter.dispatchEvent(new Event("input"));
      filter.requestSubmit();
    });
  }

  // One row menu open at a time; a click elsewhere closes it.
  document.addEventListener("click", (event) => {
    for (const menu of document.querySelectorAll("details.row-menu[open]")) {
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    }
  });
})();
