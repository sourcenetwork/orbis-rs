// Browser-side half of the passkey-sign reference app. Everything
// security-sensitive (verifying the assertion, checking ACP) happens on
// orbis-node, independently per ring node — this talks to the WebAuthn API
// and to this app's own small HTTP bridge (see src/main.rs), never to the
// ring directly (browsers can't speak gRPC).

const registerButton = document.getElementById("register");
const registerResult = document.getElementById("register-result");
const signButton = document.getElementById("sign");
const signResult = document.getElementById("sign-result");
const preDecryptButton = document.getElementById("pre-decrypt");
const preDecryptResult = document.getElementById("pre-decrypt-result");

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function base64urlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function textToHex(text) {
  return bytesToHex(new TextEncoder().encode(text));
}

async function getConfig() {
  const response = await fetch("/api/config");
  if (!response.ok) throw new Error("failed to load /api/config");
  return response.json();
}

async function postJson(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || `${path} failed with ${response.status}`);
  }
  return data;
}

registerButton.addEventListener("click", async () => {
  registerResult.textContent = "Registering…";
  registerResult.classList.remove("error");
  try {
    const config = await getConfig();
    const userId = new Uint8Array(16);
    crypto.getRandomValues(userId);
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { id: config.rp_id, name: "Orbis passkey-sign" },
        user: { id: userId, name: "orbis-user", displayName: "Orbis user" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
        authenticatorSelection: { userVerification: "preferred" },
      },
    });

    const publicKeySpki = credential.response.getPublicKey();
    if (!publicKeySpki) {
      throw new Error(
        "This authenticator/browser didn't return a public key via getPublicKey() — try a different browser.",
      );
    }
    const { did } = await postJson("/api/register", {
      public_key_spki_b64: bytesToBase64(publicKeySpki),
    });

    localStorage.setItem("passkeySignCredentialId", bytesToBase64(credential.rawId));
    localStorage.setItem("passkeySignDid", did);
    registerResult.textContent = `did = ${did}`;
  } catch (error) {
    registerResult.classList.add("error");
    registerResult.textContent = String(error);
  }
});

signButton.addEventListener("click", async () => {
  signResult.textContent = "Signing…";
  signResult.classList.remove("error");
  try {
    const credentialIdB64 = localStorage.getItem("passkeySignCredentialId");
    const did = localStorage.getItem("passkeySignDid");
    if (!credentialIdB64 || !did) {
      throw new Error("Register a passkey first (step 1).");
    }

    const config = await getConfig();
    const derivationId = document.getElementById("derivation-id").value;
    const message = document.getElementById("message").value;
    const messageHex = textToHex(message);

    const challengeInfo = await postJson("/api/challenge", {
      derivation_id: derivationId,
      message_hex: messageHex,
    });

    const credentialId = Uint8Array.from(atob(credentialIdB64), (c) => c.charCodeAt(0));
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: base64urlToBytes(challengeInfo.challenge_b64url),
        rpId: config.rp_id,
        allowCredentials: [{ id: credentialId, type: "public-key" }],
        userVerification: "preferred",
      },
    });

    const result = await postJson("/api/sign", {
      derivation_id: derivationId,
      message_hex: messageHex,
      issuer_did: did,
      authenticator_data_b64: bytesToBase64(assertion.response.authenticatorData),
      client_data_json_b64: bytesToBase64(assertion.response.clientDataJSON),
      signature_b64: bytesToBase64(assertion.response.signature),
      issued_at: challengeInfo.issued_at,
      expiry: challengeInfo.expiry,
      nonce_hex: challengeInfo.nonce_hex,
    });

    signResult.textContent = `signature = ${result.signature_hex}`;
  } catch (error) {
    signResult.classList.add("error");
    signResult.textContent = String(error);
  }
});

preDecryptButton.addEventListener("click", async () => {
  preDecryptResult.textContent = "Decrypting…";
  preDecryptResult.classList.remove("error");
  try {
    const did = localStorage.getItem("passkeySignDid");
    const credentialIdB64 = localStorage.getItem("passkeySignCredentialId");
    if (!did || !credentialIdB64) {
      throw new Error("Register a passkey first (step 1).");
    }

    const config = await getConfig();
    const ringPk = document.getElementById("pre-ring-pk").value;
    const objectId = document.getElementById("pre-object-id").value;
    const derivationHex = document.getElementById("pre-derivation").value || null;
    const salt = document.getElementById("pre-salt").value || null;

    // Builds the ephemeral PRE reader keypair server-side (it has to exist
    // before the challenge can be built — the challenge embeds rdr_pk) and
    // stashes it, keyed by request_token, until /api/pre/decrypt below.
    const challengeInfo = await postJson("/api/pre/challenge", {
      ring_pk: ringPk,
      object_id: objectId,
      issuer_did: did,
      derivation_hex: derivationHex,
      salt,
    });

    const credentialId = Uint8Array.from(atob(credentialIdB64), (c) => c.charCodeAt(0));
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: base64urlToBytes(challengeInfo.challenge_b64url),
        rpId: config.rp_id,
        allowCredentials: [{ id: credentialId, type: "public-key" }],
        userVerification: "preferred",
      },
    });

    const result = await postJson("/api/pre/decrypt", {
      request_token: challengeInfo.request_token,
      issuer_did: did,
      authenticator_data_b64: bytesToBase64(assertion.response.authenticatorData),
      client_data_json_b64: bytesToBase64(assertion.response.clientDataJSON),
      signature_b64: bytesToBase64(assertion.response.signature),
    });

    preDecryptResult.textContent = result.is_hex
      ? `plaintext (hex) = ${result.plaintext}`
      : `plaintext = ${result.plaintext}`;
  } catch (error) {
    preDecryptResult.classList.add("error");
    preDecryptResult.textContent = String(error);
  }
});
