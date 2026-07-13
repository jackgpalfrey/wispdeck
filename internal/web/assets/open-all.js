"use strict";

const button = document.querySelector("[data-open-all]");
const status = document.querySelector("[data-open-all-status]");
let pending = Array.from(document.querySelectorAll("[data-open-target]"), (link) => link.href);

function attemptOpen(urls) {
  const blocked = [];
  for (const url of urls) {
    const tab = window.open("about:blank", "_blank");
    if (!tab) {
      blocked.push(url);
      continue;
    }
    try {
      tab.opener = null;
      tab.location.replace(url);
    } catch {
      tab.close();
      blocked.push(url);
    }
  }
  return blocked;
}

function report() {
  if (pending.length === 0) {
    button.hidden = true;
    status.textContent = "All destinations were opened.";
    return;
  }
  button.hidden = false;
  status.textContent = `${pending.length} tab${pending.length === 1 ? " was" : "s were"} blocked. Use Open all to retry.`;
}

window.addEventListener("load", () => {
  pending = attemptOpen(pending);
  report();
});

button.addEventListener("click", () => {
  pending = attemptOpen(pending);
  report();
});
