"use strict";

/* ---------- explicit destructive confirmations ---------- */

document.addEventListener("submit", (event) => {
  const form = event.target.closest("form[data-confirm]");
  if (form && !window.confirm(form.dataset.confirm)) {
    event.preventDefault();
  }
});

/* ---------- server-authorized name reclamation ---------- */

for (const dialog of document.querySelectorAll("[data-confirm-dialog]")) {
  if (typeof dialog.showModal === "function") {
    dialog.removeAttribute("open");
    dialog.showModal();
  }
}

/* ---------- copy buttons ---------- */

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) {
    return;
  }
  event.preventDefault();
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.textContent = "copied";
    button.classList.add("copied");
  } catch {
    button.textContent = "failed";
  }
  window.setTimeout(() => {
    button.textContent = original;
    button.classList.remove("copied");
  }, 1400);
});

/* ---------- upload dropzones: reflect the chosen file ---------- */

for (const drop of document.querySelectorAll(".upload-drop")) {
  const input = drop.querySelector('input[type="file"]');
  const label = drop.querySelector("[data-drop-label]");
  if (!input || !label) {
    continue;
  }
  const original = label.textContent;
  input.addEventListener("change", () => {
    const file = input.files && input.files[0];
    if (file) {
      const size = file.size >= 1 << 20 ? `${(file.size / (1 << 20)).toFixed(1)} MiB` : `${Math.max(1, Math.round(file.size / 1024))} KiB`;
      label.textContent = `✓ ${file.name} · ${size} — click Upload draft`;
      drop.classList.add("has-file");
    } else {
      label.textContent = original;
      drop.classList.remove("has-file");
    }
  });
}

/* ---------- dashboard: type chips + search filter ---------- */

const rows = [...document.querySelectorAll("[data-row]")];
if (rows.length > 0 || document.querySelector("[data-filter]")) {
  const chips = [...document.querySelectorAll("[data-chip]")];
  const filter = document.querySelector("[data-filter]");
  const empty = document.querySelector("[data-filter-empty]");
  const status = document.querySelector("[data-filter-status]");
  let kind = "all";

  const apply = () => {
    const query = (filter?.value || "").trim().toLocaleLowerCase();
    let visible = 0;
    for (const row of rows) {
      const matchesKind = kind === "all" || row.dataset.row === kind;
      const matchesQuery = query === "" || (row.dataset.search || row.textContent).toLocaleLowerCase().includes(query);
      const show = matchesKind && matchesQuery;
      row.hidden = !show;
      if (show) {
        visible += 1;
      }
    }
    empty?.classList.toggle("hidden", visible !== 0 || rows.length === 0);
    if (status) {
      status.textContent = query === "" && kind === "all" ? "" : `${visible} matching ${visible === 1 ? "entry" : "entries"}`;
    }
  };

  for (const chip of chips) {
    chip.addEventListener("click", () => {
      kind = chip.dataset.chip;
      for (const other of chips) {
        other.setAttribute("aria-pressed", other === chip ? "true" : "false");
      }
      apply();
    });
  }
  filter?.addEventListener("input", apply);
}

/* ---------- link forms: destinations editor + behaviour modes ---------- */

const destinationTemplate = document.querySelector("#destination-row-template");

const modeDetails = {
  redirect: {
    summary: "Direct redirect",
    explanation: "Visitors are sent straight to your destination.",
    helper: "A direct link can have one destination.",
  },
  index: {
    summary: "Link page",
    explanation: "Visitors see a simple public page containing every destination.",
    helper: "Labels are shown publicly on the link page.",
  },
  open_all: {
    summary: "Open all",
    explanation: "Wispdeck tries to open every destination in a new tab and provides a fallback button if the browser blocks any.",
    helper: "Labels are shown on the fallback page.",
  },
};

function selectedMode(form) {
  return form.querySelector('input[name="mode"]:checked')?.value || "redirect";
}

function setMode(form, mode) {
  const input = form.querySelector(`input[name="mode"][value="${mode}"]`);
  if (input) {
    input.checked = true;
  }
}

function updateLinkForm(form) {
  const mode = selectedMode(form);
  const details = modeDetails[mode] || modeDetails.redirect;
  const destinationRows = [...form.querySelectorAll("[data-destination-row]")];
  const hasTooManyRedirectDestinations = mode === "redirect" && destinationRows.length > 1;
  form.dataset.currentMode = mode;

  const summary = form.querySelector("[data-mode-summary]");
  if (summary) {
    summary.textContent = details.summary;
  }
  const explanation = form.querySelector("[data-mode-explanation]");
  if (explanation) {
    explanation.textContent = details.explanation;
  }
  const helper = form.querySelector("[data-destination-helper]");
  if (helper) {
    helper.textContent = hasTooManyRedirectDestinations
      ? "Remove the extra destinations to use a direct redirect."
      : details.helper;
    helper.classList.toggle("validation-hint", hasTooManyRedirectDestinations);
  }
  for (const [index, row] of destinationRows.entries()) {
    const url = row.querySelector('input[name="target_url"]');
    if (url) {
      url.setCustomValidity(hasTooManyRedirectDestinations && index > 0
        ? "Remove this extra destination or choose Link page or Open all."
        : "");
    }
  }

  updateDestinationEditor(form.querySelector("[data-destinations-editor]"));
}

function updateDestinationEditor(editor) {
  if (!editor) {
    return;
  }
  const rows = editor.querySelectorAll("[data-destination-row]");
  for (const remove of editor.querySelectorAll("[data-remove-destination]")) {
    remove.disabled = rows.length <= 1;
  }
  const add = editor.querySelector("[data-add-destination]");
  if (add) {
    add.disabled = rows.length >= 25;
  }
}

for (const form of document.querySelectorAll("[data-link-form]")) {
  form.addEventListener("change", (event) => {
    if (event.target.matches('input[name="mode"]')) {
      updateLinkForm(form);
    }
  });

  const editor = form.querySelector("[data-destinations-editor]");
  editor?.addEventListener("click", (event) => {
    const remove = event.target.closest("[data-remove-destination]");
    if (remove) {
      const rows = editor.querySelectorAll("[data-destination-row]");
      if (rows.length > 1) {
        remove.closest("[data-destination-row]").remove();
        updateLinkForm(form);
      }
      return;
    }

    const add = event.target.closest("[data-add-destination]");
    if (!add || !destinationTemplate || editor.querySelectorAll("[data-destination-row]").length >= 25) {
      return;
    }
    if (selectedMode(form) === "redirect") {
      setMode(form, "index");
      const behaviorPanel = form.querySelector("[data-behavior-panel]");
      if (behaviorPanel) {
        behaviorPanel.open = true;
      }
    }
    editor.querySelector("[data-destination-rows]").append(destinationTemplate.content.cloneNode(true));
    updateLinkForm(form);
    const newestURL = editor.querySelector("[data-destination-row]:last-child input[name='target_url']");
    newestURL?.focus();
  });

  form.addEventListener("submit", () => {
    if (!form.checkValidity()) {
      return;
    }
    const submit = form.querySelector("[data-create-button]");
    if (submit) {
      submit.disabled = true;
      submit.textContent = "Working…";
    }
  });

  updateLinkForm(form);
}

const formError = document.querySelector("[data-form-error]");
if (formError) {
  formError.closest("form")?.querySelector("input:not([type='hidden'])")?.focus();
}
