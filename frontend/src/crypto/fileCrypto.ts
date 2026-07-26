/**
 * File/image crypto (US4) — encrypts shared files under the SAME
 * per-conversation message key `conversationCrypto.ts` already establishes
 * (ML-KEM-768 → HKDF-SHA3-256), so no new key material or exchange is needed.
 *
 * The filename is privacy-sensitive content the server must never see
 * (FR-051) — rather than sending it as a cleartext multipart field, it is
 * packed into the SAME plaintext buffer as the file bytes before encryption
 * (a length-prefixed frame), so it travels inside the opaque ciphertext blob.
 * `content_type`/`size_bytes` stay cleartext/declared (non-authoritative,
 * data-model.md) purely so the UI can show an image preview vs. a download
 * link without first decrypting.
 *
 * Sealing reuses the exact same AEAD + ML-DSA-65 signature scheme as
 * `sealMessage`/`openMessage` (over the file bytes instead of message text),
 * so a shared file gets the same sender-authenticity guarantee as a text
 * message (FR-027) — the AEAD tag alone only proves non-tampering, not who
 * sent it.
 */

import { aes256GcmFileCipher } from "@/crypto/providers/ciphers";
import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { base64ToBytes, bytesToBase64, concatBytes } from "@/crypto/bytes";
import type { MessageEnvelope } from "@/types/messaging";

const ALG = "aes-256-gcm";
const VERSION = 1;

/** User's product decision: 100 MB cap, PDF + any image format. Enforced
 * client-side before encryption (the server never sees plaintext bytes, so
 * it structurally cannot sniff content — FR-051) via an extension allowlist,
 * matching the "type validation by extension" choice made for this feature. */
export const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;

export const ALLOWED_FILE_EXTENSIONS = [
  ".pdf",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".svg",
  ".avif",
  ".tiff",
  ".ico",
  ".heic",
  ".heif",
];

export interface FileValidationResult {
  ok: boolean;
  reason?: string;
  contentType: string;
}

function guessContentType(filename: string): string {
  const ext = filename.toLowerCase().slice(filename.lastIndexOf("."));
  if (ext === ".pdf") return "application/pdf";
  const imageExt = ext.replace(".", "");
  const normalized = imageExt === "jpg" ? "jpeg" : imageExt;
  return `image/${normalized}`;
}

/** Validate a file against the size cap + extension allowlist BEFORE it is
 * read/encrypted — rejecting early avoids wasting time encrypting/uploading
 * something that will never be accepted. */
export function validateFileForUpload(file: File): FileValidationResult {
  const name = file.name.toLowerCase();
  const ext = name.slice(name.lastIndexOf("."));
  const contentType = guessContentType(name);
  if (!ALLOWED_FILE_EXTENSIONS.includes(ext)) {
    return { ok: false, reason: `"${ext || "unknown"}" files aren't supported — only PDF and images.`, contentType };
  }
  if (file.size <= 0) {
    return { ok: false, reason: "File is empty.", contentType };
  }
  if (file.size > MAX_FILE_SIZE_BYTES) {
    return { ok: false, reason: "File is larger than the 100 MB limit.", contentType };
  }
  return { ok: true, contentType };
}

/** Length-prefixed frame: [u16 filenameLen][filename utf8][file bytes]. */
export function packFilePlaintext(filename: string, bytes: Uint8Array): Uint8Array {
  const nameBytes = new TextEncoder().encode(filename);
  if (nameBytes.length > 0xffff) {
    throw new Error("filename too long to encode");
  }
  const header = new Uint8Array(2);
  new DataView(header.buffer).setUint16(0, nameBytes.length, false);
  return concatBytes(header, nameBytes, bytes);
}

export function unpackFilePlaintext(buf: Uint8Array): { filename: string; bytes: Uint8Array } {
  if (buf.length < 2) {
    throw new Error("malformed file plaintext frame");
  }
  const nameLength = new DataView(buf.buffer, buf.byteOffset, 2).getUint16(0, false);
  const nameStart = 2;
  const nameEnd = nameStart + nameLength;
  if (buf.length < nameEnd) {
    throw new Error("malformed file plaintext frame");
  }
  const filename = new TextDecoder().decode(buf.subarray(nameStart, nameEnd));
  const bytes = buf.subarray(nameEnd);
  return { filename, bytes };
}

function fileAssociatedData(conversationId: string, senderKeyId: string): Uint8Array {
  return new TextEncoder().encode(`${conversationId}|file|${senderKeyId}`);
}

export interface SealedFile {
  ciphertext: Uint8Array;
  envelope: MessageEnvelope;
}

/** Encrypt + sign one file's plaintext frame under the conversation key. */
export async function sealFile(
  messageKey: Uint8Array,
  plaintext: Uint8Array,
  signingPrivateKey: Uint8Array,
  conversationId: string,
  senderKeyId: string,
): Promise<SealedFile> {
  const aad = fileAssociatedData(conversationId, senderKeyId);
  const { ciphertext, nonce } = await aes256GcmFileCipher.encrypt(messageKey, plaintext, aad);
  const signature = await mlDsa65IdentityKeyProvider.sign(
    signingPrivateKey,
    concatBytes(ciphertext, nonce, aad),
  );
  return {
    ciphertext,
    envelope: { alg: ALG, nonce: bytesToBase64(nonce), version: VERSION, sig: bytesToBase64(signature) },
  };
}

export class FileAuthenticityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FileAuthenticityError";
  }
}

/** Verify authorship + decrypt one file's ciphertext under the conversation
 * key, returning the unpacked filename + bytes. Throws `FileAuthenticityError`
 * if the signature does not verify (FR-027). */
export async function openFile(
  messageKey: Uint8Array,
  ciphertext: Uint8Array,
  envelope: MessageEnvelope,
  senderSigningPublicKey: Uint8Array,
  conversationId: string,
  senderKeyId: string,
): Promise<{ filename: string; bytes: Uint8Array }> {
  const nonce = base64ToBytes(String(envelope.nonce));
  const signatureB64 = envelope.sig;
  if (typeof signatureB64 !== "string") {
    throw new FileAuthenticityError("missing signature");
  }
  const aad = fileAssociatedData(conversationId, senderKeyId);
  const valid = await mlDsa65IdentityKeyProvider.verify(
    senderSigningPublicKey,
    concatBytes(ciphertext, nonce, aad),
    base64ToBytes(signatureB64),
  );
  if (!valid) {
    throw new FileAuthenticityError("signature did not verify");
  }
  const plaintext = await aes256GcmFileCipher.decrypt(messageKey, { ciphertext, nonce }, aad);
  return unpackFilePlaintext(plaintext);
}
