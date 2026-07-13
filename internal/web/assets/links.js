"use strict";

document.documentElement.classList.add("js");

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
      submit.textContent = "Creating link…";
    }
  });

  updateLinkForm(form);
}

const formError = document.querySelector("[data-form-error]");
if (formError) {
  formError.closest("form")?.querySelector("input:not([type='hidden'])")?.focus();
}

const filter = document.querySelector("[data-link-filter]");
const records = [...document.querySelectorAll("[data-link-record]")];
if (filter && records.length > 0) {
  const empty = document.querySelector("[data-filter-empty]");
  const status = document.querySelector("[data-filter-status]");
  filter.addEventListener("input", () => {
    const query = filter.value.trim().toLocaleLowerCase();
    let visible = 0;
    for (const record of records) {
      const matches = query === "" || record.textContent.toLocaleLowerCase().includes(query);
      record.hidden = !matches;
      if (matches) {
        visible += 1;
      }
    }
    empty?.classList.toggle("hidden", visible !== 0);
    if (status) {
      status.textContent = query === "" ? "" : `${visible} matching ${visible === 1 ? "link" : "links"}`;
    }
  });
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) {
    return;
  }
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.textContent = "Copied!";
    button.classList.add("copied");
  } catch {
    button.textContent = "Copy failed";
  }
  window.setTimeout(() => {
    button.textContent = original;
    button.classList.remove("copied");
  }, 1600);
});
