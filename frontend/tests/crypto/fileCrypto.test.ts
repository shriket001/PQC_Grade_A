import { describe, expect, it } from "vitest";

import {
  ALLOWED_FILE_EXTENSIONS,
  FileAuthenticityError,
  MAX_FILE_SIZE_BYTES,
  openFile,
  packFilePlaintext,
  sealFile,
  unpackFilePlaintext,
  validateFileForUpload,
} from "@/crypto/fileCrypto";
import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";

const CONV_ID = "11111111-1111-1111-1111-111111111111";
const SENDER_KEY_ID = "22222222-2222-2222-2222-222222222222";

describe("fileCrypto — pack/unpack plaintext framing", () => {
  it("round-trips filename + bytes", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(64));
    const packed = packFilePlaintext("report.pdf", bytes);
    const { filename, bytes: recovered } = unpackFilePlaintext(packed);
    expect(filename).toBe("report.pdf");
    expect(recovered).toEqual(bytes);
  });

  it("round-trips an empty filename", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const packed = packFilePlaintext("", bytes);
    const { filename, bytes: recovered } = unpackFilePlaintext(packed);
    expect(filename).toBe("");
    expect(recovered).toEqual(bytes);
  });

  it("throws on a truncated frame", () => {
    expect(() => unpackFilePlaintext(new Uint8Array([0]))).toThrow();
  });
});

describe("fileCrypto — seal/open round trip", () => {
  it("encrypts + signs, then decrypts + verifies a file", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const signer = await mlDsa65IdentityKeyProvider.generateKeyPair();
    const plaintext = packFilePlaintext("photo.png", crypto.getRandomValues(new Uint8Array(256)));

    const sealed = await sealFile(key, plaintext, signer.privateKey, CONV_ID, SENDER_KEY_ID);
    const { filename, bytes } = await openFile(
      key,
      sealed.ciphertext,
      sealed.envelope,
      signer.publicKey,
      CONV_ID,
      SENDER_KEY_ID,
    );
    expect(filename).toBe("photo.png");
    expect(bytes).toEqual(unpackFilePlaintext(plaintext).bytes);
  });

  it("rejects a tampered ciphertext", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const signer = await mlDsa65IdentityKeyProvider.generateKeyPair();
    const plaintext = packFilePlaintext("doc.pdf", new Uint8Array([9, 9, 9]));
    const sealed = await sealFile(key, plaintext, signer.privateKey, CONV_ID, SENDER_KEY_ID);

    const tampered = sealed.ciphertext.slice();
    tampered[0] ^= 0xff;
    await expect(
      openFile(key, tampered, sealed.envelope, signer.publicKey, CONV_ID, SENDER_KEY_ID),
    ).rejects.toThrow();
  });

  it("rejects a signature from a different signing key", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const signer = await mlDsa65IdentityKeyProvider.generateKeyPair();
    const otherSigner = await mlDsa65IdentityKeyProvider.generateKeyPair();
    const plaintext = packFilePlaintext("doc.pdf", new Uint8Array([1, 2, 3]));
    const sealed = await sealFile(key, plaintext, signer.privateKey, CONV_ID, SENDER_KEY_ID);

    await expect(
      openFile(key, sealed.ciphertext, sealed.envelope, otherSigner.publicKey, CONV_ID, SENDER_KEY_ID),
    ).rejects.toThrow(FileAuthenticityError);
  });

  it("rejects the wrong AAD binding (different conversation id)", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const signer = await mlDsa65IdentityKeyProvider.generateKeyPair();
    const plaintext = packFilePlaintext("doc.pdf", new Uint8Array([1, 2, 3]));
    const sealed = await sealFile(key, plaintext, signer.privateKey, CONV_ID, SENDER_KEY_ID);

    await expect(
      openFile(
        key,
        sealed.ciphertext,
        sealed.envelope,
        signer.publicKey,
        "99999999-9999-9999-9999-999999999999",
        SENDER_KEY_ID,
      ),
    ).rejects.toThrow();
  });
});

describe("fileCrypto — validateFileForUpload", () => {
  function makeFile(name: string, size: number): File {
    return new File([new Uint8Array(Math.max(size, 0))], name);
  }

  it("accepts a PDF within the size cap", () => {
    const result = validateFileForUpload(makeFile("report.pdf", 1024));
    expect(result.ok).toBe(true);
    expect(result.contentType).toBe("application/pdf");
  });

  it("accepts an image with a normalized content type", () => {
    const result = validateFileForUpload(makeFile("photo.jpg", 1024));
    expect(result.ok).toBe(true);
    expect(result.contentType).toBe("image/jpeg");
  });

  it("rejects a disallowed extension", () => {
    const result = validateFileForUpload(makeFile("archive.zip", 1024));
    expect(result.ok).toBe(false);
  });

  it("rejects a file over the 100 MB cap", () => {
    // Avoid actually allocating 100MB+1 in the test file body; File's `size`
    // is what validateFileForUpload reads, not the backing buffer length.
    const file = makeFile("big.png", 0);
    Object.defineProperty(file, "size", { value: MAX_FILE_SIZE_BYTES + 1 });
    const result = validateFileForUpload(file);
    expect(result.ok).toBe(false);
  });

  it("rejects an empty file", () => {
    const result = validateFileForUpload(makeFile("empty.png", 0));
    expect(result.ok).toBe(false);
  });

  it("every declared allowed extension validates as ok for a nonzero size", () => {
    for (const ext of ALLOWED_FILE_EXTENSIONS) {
      const result = validateFileForUpload(makeFile(`file${ext}`, 10));
      expect(result.ok).toBe(true);
    }
  });
});
