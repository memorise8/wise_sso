(() => {
  // Loaded without defer so the saved theme applies before the first paint.
  const key = "wise_sso_admin_theme";
  const read = () => {
    try {
      return window.localStorage.getItem(key);
    } catch {
      return null;
    }
  };
  const apply = (theme) => {
    if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
  };
  apply(read());

  document.addEventListener("DOMContentLoaded", () => {
    const buttons = [...document.querySelectorAll("[data-theme-choice]")];
    const mark = (theme) => {
      for (const button of buttons) {
        button.setAttribute("aria-pressed", String(button.dataset.themeChoice === (theme ?? "system")));
      }
    };
    mark(read());
    for (const button of buttons) {
      button.addEventListener("click", () => {
        const theme = button.dataset.themeChoice === "system" ? null : button.dataset.themeChoice;
        try {
          if (theme) window.localStorage.setItem(key, theme);
          else window.localStorage.removeItem(key);
        } catch {
          // Without storage the choice still applies until the page is closed.
        }
        apply(theme);
        mark(theme);
      });
    }
  });
})();
