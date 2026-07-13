"use strict";

const destinationTemplate = document.querySelector("#destination-row-template");

function updateDestinationEditor(editor) {
  const rows = editor.querySelectorAll("[data-destination-row]");
  for (const remove of editor.querySelectorAll("[data-remove-destination]")) {
    remove.disabled = rows.length <= 1;
  }
  const add = editor.querySelector("[data-add-destination]");
  if (add) {
    add.disabled = rows.length >= 25;
  }
}

for (const editor of document.querySelectorAll("[data-destinations-editor]")) {
  editor.addEventListener("click", (event) => {
    const remove = event.target.closest("[data-remove-destination]");
    if (remove) {
      const rows = editor.querySelectorAll("[data-destination-row]");
      if (rows.length > 1) {
        remove.closest("[data-destination-row]").remove();
        updateDestinationEditor(editor);
      }
      return;
    }
    const add = event.target.closest("[data-add-destination]");
    if (add && destinationTemplate && editor.querySelectorAll("[data-destination-row]").length < 25) {
      editor.querySelector("[data-destination-rows]").append(destinationTemplate.content.cloneNode(true));
      updateDestinationEditor(editor);
    }
  });
  updateDestinationEditor(editor);
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) {
    return;
  }
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.textContent = "Copied";
  } catch {
    button.textContent = "Copy failed";
  }
  window.setTimeout(() => {
    button.textContent = original;
  }, 1500);
});
