"use strict";
// Loaded without `defer` so the theme applies before first paint.
(function () {
  document.documentElement.classList.remove("no-js");

  let stored = null;
  try {
    stored = localStorage.getItem("wispdeck-theme");
  } catch {
    // Storage may be unavailable; fall back to the system preference.
  }
  const system = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.dataset.theme = stored === "dark" || stored === "light" ? stored : system;

  document.addEventListener("click", (event) => {
    if (!event.target.closest("[data-theme-toggle]")) {
      return;
    }
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("wispdeck-theme", next);
    } catch {
      // Ignore storage failures; the choice simply won't persist.
    }
  });
})();
