import { base64UrlToBytes, bytesToBase64Url } from "./base64url";

export type CreationOptions = {
  challenge: string;
  rpId: string;
  rpName: string;
  userHandle: string;
  userName: string;
  userDisplayName: string;
  timeout: number;
};

export type RequestOptions = {
  challenge: string;
  rpId: string;
  allowCredentials: { type: "public-key"; id: string }[];
  userVerification: "required";
  timeout: number;
};

export type CeremonyResult = {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature?: string;
  publicKey?: string;
};

/** Asks the browser to create a passkey and returns the fields the API verifies. */
export async function createPasskey(
  options: CreationOptions,
): Promise<CeremonyResult> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: toBuffer(base64UrlToBytes(options.challenge)),
      rp: { name: options.rpName, id: options.rpId },
      user: {
        id: toBuffer(base64UrlToBytes(options.userHandle)),
        name: options.userName,
        displayName: options.userDisplayName,
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        userVerification: "required",
        residentKey: "preferred",
      },
      attestation: "none",
      timeout: options.timeout,
    },
  })) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error("The passkey was not created.");
  }
  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKey = response.getPublicKey();
  if (!publicKey) {
    throw new Error("This browser did not provide a public key.");
  }
  return {
    credentialId: bytesToBase64Url(new Uint8Array(credential.rawId)),
    clientDataJSON: bytesToBase64Url(new Uint8Array(response.clientDataJSON)),
    authenticatorData: bytesToBase64Url(
      new Uint8Array(response.getAuthenticatorData()),
    ),
    publicKey: bytesToBase64Url(new Uint8Array(publicKey)),
  };
}

/** Asks the browser to sign in with an existing passkey. */
export async function getPasskey(
  options: RequestOptions,
): Promise<CeremonyResult> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: toBuffer(base64UrlToBytes(options.challenge)),
      rpId: options.rpId,
      allowCredentials: options.allowCredentials.map((item) => ({
        type: "public-key" as const,
        id: toBuffer(base64UrlToBytes(item.id)),
      })),
      userVerification: "required",
      timeout: options.timeout,
    },
  })) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error("Sign-in was cancelled.");
  }
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    credentialId: bytesToBase64Url(new Uint8Array(credential.rawId)),
    clientDataJSON: bytesToBase64Url(new Uint8Array(response.clientDataJSON)),
    authenticatorData: bytesToBase64Url(
      new Uint8Array(response.authenticatorData),
    ),
    signature: bytesToBase64Url(new Uint8Array(response.signature)),
  };
}

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}
