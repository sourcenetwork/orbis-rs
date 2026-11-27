// Browser-side half of the email-decrypt reference app. Everything
// security-sensitive (verifying the DKIM-signed reply, checking ACP)
// happens on orbis-node, independently per ring node — this talks only
// to this app's own small HTTP bridge (see src/main.rs), which does the
// SMTP send / IMAP check; never to the ring directly (browsers can't
// speak gRPC, and shouldn't hold Gmail credentials either).

const didLookupButton = document.getElementById("did-lookup");
const didResult = document.getElementById("did-result");

const signChallengeButton = document.getElementById("sign-challenge");
const signCheckButton = document.getElementById("sign-check");
const signChallengeText = document.getElementById("sign-challenge-text");
const signResult = document.getElementById("sign-result");

const preChallengeButton = document.getElementById("pre-challenge");
const preCheckButton = document.getElementById("pre-check");
const preChallengeText = document.getElementById("pre-challenge-text");
const preResult = document.getElementById("pre-result");

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function textToHex(text) {
  return bytesToHex(new TextEncoder().encode(text));
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

didLookupButton.addEventListener("click", async () => {
  didResult.textContent = "Looking up…";
  didResult.classList.remove("error");
  try {
    const address = document.getElementById("did-address").value;
    const response = await postJson("/api/email-did", { address });
    didResult.textContent = response.did;
  } catch (error) {
    didResult.classList.add("error");
    didResult.textContent = String(error);
  }
});

let signRequestToken = null;

signChallengeButton.addEventListener("click", async () => {
  signResult.textContent = "—";
  signResult.classList.remove("error");
  signChallengeText.textContent = "Sending…";
  try {
    const address = document.getElementById("sign-address").value;
    const derivationId = document.getElementById("derivation-id").value;
    const message = document.getElementById("message").value;

    const response = await postJson("/api/sign/challenge", {
      derivation_id: derivationId,
      message_hex: textToHex(message),
      claimed_address: address,
    });

    signRequestToken = response.request_token;
    signChallengeText.textContent = response.confirmation_block;
  } catch (error) {
    signChallengeText.classList.add("error");
    signChallengeText.textContent = String(error);
  }
});

signCheckButton.addEventListener("click", async () => {
  if (!signRequestToken) {
    signResult.classList.add("error");
    signResult.textContent = "Send a challenge email first (step 1).";
    return;
  }
  signResult.textContent = "Checking…";
  signResult.classList.remove("error");
  try {
    const response = await postJson("/api/sign/check-reply", {
      request_token: signRequestToken,
    });
    signResult.textContent = response.found
      ? `signature = ${response.signature_hex}`
      : "No reply found yet — try again in a moment.";
  } catch (error) {
    signResult.classList.add("error");
    signResult.textContent = String(error);
  }
});

let preRequestToken = null;

preChallengeButton.addEventListener("click", async () => {
  preResult.textContent = "—";
  preResult.classList.remove("error");
  preChallengeText.textContent = "Sending…";
  try {
    const address = document.getElementById("pre-address").value;
    const ringPk = document.getElementById("pre-ring-pk").value;
    const objectId = document.getElementById("pre-object-id").value;
    const derivationHex = document.getElementById("pre-derivation").value || null;
    const salt = document.getElementById("pre-salt").value || null;

    const response = await postJson("/api/pre/challenge", {
      ring_pk: ringPk,
      object_id: objectId,
      claimed_address: address,
      derivation_hex: derivationHex,
      salt,
    });

    preRequestToken = response.request_token;
    preChallengeText.textContent = response.confirmation_block;
  } catch (error) {
    preChallengeText.classList.add("error");
    preChallengeText.textContent = String(error);
  }
});

preCheckButton.addEventListener("click", async () => {
  if (!preRequestToken) {
    preResult.classList.add("error");
    preResult.textContent = "Send a challenge email first (step 2).";
    return;
  }
  preResult.textContent = "Checking…";
  preResult.classList.remove("error");
  try {
    const response = await postJson("/api/pre/check-reply", {
      request_token: preRequestToken,
    });
    if (!response.found) {
      preResult.textContent = "No reply found yet — try again in a moment.";
    } else {
      preResult.textContent = response.is_hex
        ? `plaintext (hex) = ${response.plaintext}`
        : `plaintext = ${response.plaintext}`;
    }
  } catch (error) {
    preResult.classList.add("error");
    preResult.textContent = String(error);
  }
});
