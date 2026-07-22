const form = document.querySelector("#new-item-form");
const input = document.querySelector("#new-item");
const list = document.querySelector("#checklist-items");
const status = document.querySelector("#checklist-status");
const checklist = wispist.collection("before-you-go");

let documents = new Map();

function showError(error) {
  if (error && error.code === "revision_conflict") {
    status.textContent = "Somebody else changed that item. The latest version will appear in a moment.";
    return;
  }
  status.textContent = error && error.detail
    ? error.detail
    : "The shared checklist is temporarily unavailable.";
}

function render(items) {
  documents = new Map(items.map((item) => [item.id, item]));
  list.replaceChildren();
  for (const item of items) {
    const row = document.createElement("li");
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    const text = document.createElement("span");
    const remove = document.createElement("button");

    checkbox.type = "checkbox";
    checkbox.checked = Boolean(item.data.done);
    checkbox.disabled = wispist.readOnly;
    checkbox.dataset.id = item.id;
    text.textContent = String(item.data.text || "Untitled item");
    remove.type = "button";
    remove.className = "remove-item";
    remove.dataset.id = item.id;
    remove.textContent = "Remove";
    remove.disabled = wispist.readOnly;
    label.append(checkbox, text);
    row.append(label, remove);
    list.append(row);
  }
  status.textContent = wispist.readOnly
    ? "Viewing live data in read-only preview mode."
    : items.length === 0
      ? "Nothing here yet. Add the first item."
      : `${items.length} shared ${items.length === 1 ? "item" : "items"}.`;
}

function renderDocuments() {
  render([...documents.values()]);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = input.value.trim();
  if (!text || wispist.readOnly) return;
  form.querySelector("button").disabled = true;
  try {
    const created = await checklist.add({ text, done: false });
    documents.set(created.id, created);
    renderDocuments();
    input.value = "";
    input.focus();
  } catch (error) {
    showError(error);
  } finally {
    form.querySelector("button").disabled = false;
  }
});

list.addEventListener("change", async (event) => {
  const checkbox = event.target.closest('input[type="checkbox"][data-id]');
  const item = checkbox && documents.get(checkbox.dataset.id);
  if (!item) return;
  checkbox.disabled = true;
  try {
    const updated = await checklist.update(item, { done: checkbox.checked });
    documents.set(updated.id, updated);
    renderDocuments();
  } catch (error) {
    checkbox.checked = Boolean(item.data.done);
    showError(error);
  }
});

list.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-id]");
  const item = button && documents.get(button.dataset.id);
  if (!item) return;
  button.disabled = true;
  try {
    await checklist.delete(item);
    documents.delete(item.id);
    renderDocuments();
  } catch (error) {
    button.disabled = false;
    showError(error);
  }
});

if (wispist.readOnly) {
  form.hidden = true;
}

checklist.subscribe(render, { onError: showError });
