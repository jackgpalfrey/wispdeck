(() => {
  "use strict";

  if (Object.prototype.hasOwnProperty.call(globalThis, "wispist")) return;

  const API = "/_wispist/v1";
  const PROBLEMS = "https://learn.peios.org/wispist/problems/";
  const knownCodes = new Map([
    ["invalid-request/", "invalid_request"],
    ["invalid-json/", "invalid_json"],
    ["authentication-required/", "authentication_required"],
    ["forbidden/", "forbidden"],
    ["not-found/", "not_found"],
    ["idempotency-conflict/", "idempotency_conflict"],
    ["quota-exceeded/", "quota_exceeded"],
    ["revision-conflict/", "revision_conflict"],
    ["request-too-large/", "request_too_large"],
    ["unsupported-media-type/", "unsupported_media_type"],
    ["method-not-allowed/", "method_not_allowed"],
    ["precondition-required/", "precondition_required"],
    ["rate-limited/", "rate_limited"],
    ["temporarily-unavailable/", "temporarily_unavailable"],
  ]);
  const collectionPattern = /^[a-z][a-z0-9_-]{0,47}$/;
  const documentPattern = /^[A-Za-z0-9_-]{1,64}$/;

  class WispistError extends Error {
    constructor({ type = null, title = "Wispist request failed", detail = "", status = null, instance = null, requestId = null, problem = null, code = "unknown_problem", cause = null }) {
      super(detail || title, cause ? { cause } : undefined);
      this.name = "WispistError";
      this.type = type;
      this.code = code;
      this.title = title;
      this.detail = detail;
      this.status = status;
      this.instance = instance;
      this.requestId = requestId;
      this.problem = problem;
    }
  }

  function codeForType(type) {
    if (typeof type !== "string" || !type.startsWith(PROBLEMS)) return "unknown_problem";
    return knownCodes.get(type.slice(PROBLEMS.length)) || "unknown_problem";
  }

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json, application/problem+json");
    let response;
    try {
      response = await fetch(path, {
        ...options,
        headers,
        cache: "no-store",
        credentials: "same-origin",
      });
    } catch (cause) {
      if (cause && cause.name === "AbortError") throw cause;
      throw new WispistError({ code: "network_error", title: "Network error", detail: "The Wispist request could not reach the server.", cause });
    }
    if (!response.ok) throw await errorFromResponse(response);
    if (response.status === 204) return null;
    try {
      return await response.json();
    } catch (cause) {
      throw new WispistError({
        code: "invalid_response",
        title: "Invalid response",
        detail: "The Wispist server returned an invalid JSON response.",
        status: response.status,
        requestId: response.headers.get("X-Request-ID"),
        cause,
      });
    }
  }

  async function errorFromResponse(response) {
    let problem = null;
    try {
      problem = await response.json();
    } catch (_) {
      // Preserve the HTTP failure without fabricating Problem Details.
    }
    const type = problem && typeof problem.type === "string" ? problem.type : null;
    return new WispistError({
      type,
      code: codeForType(type),
      title: problem && typeof problem.title === "string" ? problem.title : "Wispist request failed",
      detail: problem && typeof problem.detail === "string" ? problem.detail : `The server returned HTTP ${response.status}.`,
      status: response.status,
      instance: problem && typeof problem.instance === "string" ? problem.instance : null,
      requestId: response.headers.get("X-Request-ID"),
      problem,
    });
  }

  function assertData(data) {
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw new TypeError("Wispist document data must be an object");
    }
  }

  function assertDocument(document) {
    if (!document || typeof document !== "object" || !documentPattern.test(document.id || "") || typeof document.revision !== "string") {
      throw new TypeError("A Wispist document with an observed revision is required");
    }
    assertData(document.data);
  }

  function documentPath(collection, id = "") {
    const base = `${API}/collections/${encodeURIComponent(collection)}/documents`;
    return id ? `${base}/${encodeURIComponent(id)}` : base;
  }

  function newIdempotencyKey() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  }

  async function listState(collection, options = {}, signal = undefined) {
    const pageLimit = options.limit === undefined ? 250 : options.limit;
    if (!Number.isInteger(pageLimit) || pageLimit < 1 || pageLimit > 250) {
      throw new RangeError("Wispist list limit must be an integer between 1 and 250");
    }
    const documents = [];
    let after = null;
    let changes = null;
    do {
      const query = new URLSearchParams({ limit: String(pageLimit) });
      if (after) query.set("after", after);
      const page = await request(`${documentPath(collection)}?${query}`, { signal });
      if (!page || !Array.isArray(page.documents) || typeof page.changes !== "string") {
        throw new WispistError({ code: "invalid_response", title: "Invalid response", detail: "The Wispist list response is incomplete." });
      }
      if (changes === null) changes = page.changes;
      documents.push(...page.documents);
      after = typeof page.after === "string" && page.after ? page.after : null;
    } while (after);
    return { documents, changes };
  }

  function collection(name) {
    if (!collectionPattern.test(name)) {
      throw new TypeError("Invalid Wispist collection name");
    }

    const handle = {
      async list(options) {
        return (await listState(name, options)).documents;
      },

      get(id) {
        if (!documentPattern.test(id)) throw new TypeError("Invalid Wispist document ID");
        return request(documentPath(name, id));
      },

      add(data) {
        assertData(data);
        return request(documentPath(name), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": newIdempotencyKey(),
          },
          body: JSON.stringify({ data }),
        });
      },

      create(id, data) {
        if (!documentPattern.test(id) || id === "." || id === "..") throw new TypeError("Invalid Wispist document ID");
        assertData(data);
        return request(documentPath(name, id), {
          method: "PUT",
          headers: { "Content-Type": "application/json", "If-None-Match": "*" },
          body: JSON.stringify({ data }),
        });
      },

      replace(document, data) {
        assertDocument(document);
        assertData(data);
        return request(documentPath(name, document.id), {
          method: "PUT",
          headers: { "Content-Type": "application/json", "If-Match": `"${document.revision}"` },
          body: JSON.stringify({ data }),
        });
      },

      update(document, changes) {
        assertDocument(document);
        assertData(changes);
        const data = { ...document.data };
        for (const [key, value] of Object.entries(changes)) {
          if (value !== undefined) data[key] = value;
        }
        return handle.replace(document, data);
      },

      async delete(document) {
        assertDocument(document);
        await request(documentPath(name, document.id), {
          method: "DELETE",
          headers: { "If-Match": `"${document.revision}"` },
        });
      },

      subscribe(callback, options = {}) {
        if (typeof callback !== "function") throw new TypeError("Wispist subscribe requires a callback");
        const onError = typeof options.onError === "function" ? options.onError : () => {};
        let stopped = false;
        let source = null;
        let timer = null;
        let backoff = 500;
        let cursor = null;
        let listing = null;
        const documents = new Map();

        const snapshot = () => [...documents.values()];
        const emit = (event) => {
          if (stopped) return;
          try {
            callback(snapshot(), event);
          } catch (error) {
            queueMicrotask(() => { throw error; });
          }
        };
        const report = (error) => {
          try { onError(error); } catch (callbackError) { queueMicrotask(() => { throw callbackError; }); }
        };
        const schedule = (relist = false) => {
          if (stopped || timer !== null) return;
          const delay = Math.round(backoff * (0.75 + Math.random() * 0.5));
          backoff = Math.min(backoff * 2, 30_000);
          timer = setTimeout(() => {
            timer = null;
            if (relist) start(); else open();
          }, delay);
        };
        const open = () => {
          if (stopped || !cursor) return;
          const query = new URLSearchParams({ after: cursor });
          query.append("collections", name);
          source = new EventSource(`${API}/changes?${query}`);
          source.addEventListener("open", () => { backoff = 500; });
          source.addEventListener("change", (event) => {
            try {
              const change = JSON.parse(event.data);
              if (change.operation === "delete") documents.delete(change.id);
              else if (change.document) documents.set(change.document.id, change.document);
              if (event.lastEventId) cursor = event.lastEventId;
              emit(change);
            } catch (error) {
              report(new WispistError({ code: "invalid_response", title: "Invalid change", detail: "The Wispist change stream returned an invalid event.", cause: error }));
              source.close();
              schedule(true);
            }
          });
          source.addEventListener("reset", () => {
            source.close();
            schedule(true);
          });
          source.onerror = () => {
            source.close();
            schedule(false);
          };
        };
        const start = async () => {
          if (stopped) return;
          if (source) source.close();
          if (listing) listing.abort();
          const attempt = new AbortController();
          listing = attempt;
          try {
            const state = await listState(name, options, attempt.signal);
            if (stopped) return;
            documents.clear();
            for (const document of state.documents) documents.set(document.id, document);
            cursor = state.changes;
            emit({ type: "initial" });
            backoff = 500;
            open();
          } catch (error) {
            if (error && error.name === "AbortError") return;
            report(error);
            schedule(true);
          } finally {
            if (listing === attempt) listing = null;
          }
        };

        start();
        return () => {
          if (stopped) return;
          stopped = true;
          if (source) source.close();
          if (listing) listing.abort();
          if (timer !== null) clearTimeout(timer);
        };
      },
    };

    return Object.freeze(handle);
  }

  const script = document.currentScript;
  const mode = script && script.dataset.wispistMode ? script.dataset.wispistMode : "unknown";
  const readOnly = script ? script.dataset.wispistReadOnly === "true" : false;
  const api = Object.freeze({ version: 1, mode, readOnly, collection });
  Object.defineProperty(globalThis, "wispist", {
    value: api,
    enumerable: false,
    writable: false,
    configurable: false,
  });
})();
