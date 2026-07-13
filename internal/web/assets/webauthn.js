"use strict";

function decodeBase64URL(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const bytes = Uint8Array.from(atob(padded), character => character.charCodeAt(0));
  return bytes.buffer;
}

function encodeBase64URL(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function creationOptions(options) {
  const value = options.publicKey;
  value.challenge = decodeBase64URL(value.challenge);
  value.user.id = decodeBase64URL(value.user.id);
  value.excludeCredentials = (value.excludeCredentials || []).map(item => ({
    ...item,
    id: decodeBase64URL(item.id),
  }));
  return value;
}

function requestOptions(options) {
  const value = options.publicKey;
  value.challenge = decodeBase64URL(value.challenge);
  value.allowCredentials = (value.allowCredentials || []).map(item => ({
    ...item,
    id: decodeBase64URL(item.id),
  }));
  return value;
}

function credentialJSON(credential) {
  const response = {
    clientDataJSON: encodeBase64URL(credential.response.clientDataJSON),
  };
  if (credential.response.attestationObject) {
    response.attestationObject = encodeBase64URL(credential.response.attestationObject);
    if (credential.response.getTransports) response.transports = credential.response.getTransports();
  } else {
    response.authenticatorData = encodeBase64URL(credential.response.authenticatorData);
    response.signature = encodeBase64URL(credential.response.signature);
    response.userHandle = credential.response.userHandle ? encodeBase64URL(credential.response.userHandle) : null;
  }
  return {
    id: credential.id,
    rawId: encodeBase64URL(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response,
  };
}

async function jsonRequest(path, options = {}) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    ...options,
  });
  const body = await response.json().catch(() => ({error: "Unexpected server response."}));
  if (!response.ok) throw new Error(body.error || "Request failed.");
  return body;
}

function showError(error) {
  const status = document.querySelector("#passkey-status");
  if (!status) return;
  status.textContent = error instanceof Error ? error.message : "Passkey operation failed.";
  status.classList.remove("hidden");
}

const loginButton = document.querySelector("[data-passkey-login]");
const anotherFactorButton = document.querySelector("[data-use-another-factor]");
let loginAbortController = null;

function focusFallbackFactor() {
  const totpInput = document.querySelector("#totp-code");
  if (totpInput) {
    totpInput.focus();
    totpInput.select();
    return;
  }
  const recoverySummary = document.querySelector("details summary");
  if (recoverySummary) {
    const recoveryDetails = recoverySummary.parentElement;
    if (recoveryDetails && !recoveryDetails.open) {
      recoveryDetails.open = true;
    }
    const recoveryInput = document.querySelector("#recovery-code");
    if (recoveryInput) {
      recoveryInput.focus();
      recoveryInput.select();
      return;
    }
    recoverySummary.focus();
  }
}

if (loginButton) {
  loginButton.addEventListener("click", async () => {
    loginButton.disabled = true;
    if (anotherFactorButton) anotherFactorButton.disabled = false;
    loginAbortController = typeof AbortController === "function" ? new AbortController() : null;
    try {
      if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
      const options = await jsonRequest("/api/auth/passkey/login/begin");
      const publicKeyRequest = {publicKey: requestOptions(options)};
      if (loginAbortController) publicKeyRequest.signal = loginAbortController.signal;
      const credential = await navigator.credentials.get(publicKeyRequest);
      const result = await jsonRequest("/api/auth/passkey/login/finish", {
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(credentialJSON(credential)),
      });
      window.location.assign(result.redirect);
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        loginButton.disabled = false;
        return;
      }
      showError(error);
      loginButton.disabled = false;
      if (anotherFactorButton) anotherFactorButton.disabled = false;
    } finally {
      loginAbortController = null;
    }
  });
}

if (anotherFactorButton) {
  anotherFactorButton.addEventListener("click", () => {
    if (loginAbortController) {
      loginAbortController.abort();
    }
    if (loginButton) {
      loginButton.disabled = false;
    }
    const status = document.querySelector("#passkey-status");
    if (status) {
      status.classList.add("hidden");
      status.textContent = "";
    }
    focusFallbackFactor();
  });
}

const registerSection = document.querySelector("[data-passkey-register]");
if (registerSection) {
  const registerButton = registerSection.querySelector("[data-register-button]");
  registerButton.addEventListener("click", async () => {
    registerButton.disabled = true;
    try {
      if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
      const name = registerSection.querySelector("#passkey-name").value;
      const csrf = registerSection.dataset.csrfToken;
      const options = await jsonRequest("/api/auth/passkey/register/begin", {
        headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        body: JSON.stringify({name}),
      });
      const credential = await navigator.credentials.create({publicKey: creationOptions(options)});
      const result = await jsonRequest("/api/auth/passkey/register/finish", {
        headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        body: JSON.stringify(credentialJSON(credential)),
      });
      if (result.recovery_codes && result.recovery_codes.length) {
        const section = document.querySelector("#recovery-codes");
        const list = document.querySelector("#recovery-code-list");
        for (const code of result.recovery_codes) {
          const item = document.createElement("li");
          const value = document.createElement("code");
          value.textContent = code;
          item.appendChild(value);
          list.appendChild(item);
        }
        section.classList.remove("hidden");
        registerSection.classList.add("hidden");
      } else {
        window.location.assign(result.redirect);
      }
    } catch (error) {
      showError(error);
      registerButton.disabled = false;
    }
  });
}

const copyButton = document.querySelector("[data-copy-codes]");
if (copyButton) {
  copyButton.addEventListener("click", async () => {
    const codes = [...document.querySelectorAll("#recovery-code-list code")].map(node => node.textContent).join("\n");
    await navigator.clipboard.writeText(codes);
    copyButton.textContent = "Copied";
  });
}
