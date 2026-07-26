/**
 * File-sharing service — typed wrapper over the US4 REST contract
 * (`/api/v1/conversations/{id}/files`). Transports only ciphertext + envelope
 * metadata — file content is encrypted/decrypted exclusively in
 * `crypto/fileCrypto.ts` (FR-051).
 */

import { apiClient } from "@/services/apiClient";
import type { FileUploadResponse, MessageEnvelope } from "@/types/messaging";

export interface UploadFileInput {
  senderIdentityKeyId: string;
  fileEnvelope: MessageEnvelope;
  contentType: string;
  ciphertext: Uint8Array;
}

export async function uploadFile(
  conversationId: string,
  input: UploadFileInput,
): Promise<FileUploadResponse> {
  const form = new FormData();
  form.set("sender_identity_key_id", input.senderIdentityKeyId);
  form.set("file_envelope", JSON.stringify(input.fileEnvelope));
  form.set("content_type", input.contentType);
  form.set("size_bytes", String(input.ciphertext.length));
  form.set("file_ciphertext", new Blob([input.ciphertext.slice()]), "blob.bin");
  return apiClient.postForm<FileUploadResponse>(`/conversations/${conversationId}/files`, form);
}

export interface DownloadedFile {
  ciphertext: Uint8Array;
  envelope: MessageEnvelope;
  contentType: string;
}

export async function downloadFile(
  conversationId: string,
  fileId: string,
): Promise<DownloadedFile> {
  const { blob, headers } = await apiClient.getBinary(
    `/conversations/${conversationId}/files/${fileId}`,
  );
  const envelopeHeader = headers.get("x-file-envelope");
  const contentType = headers.get("x-file-content-type") ?? "application/octet-stream";
  if (!envelopeHeader) {
    throw new Error("file download missing envelope metadata");
  }
  const envelope = JSON.parse(envelopeHeader) as MessageEnvelope;
  const ciphertext = new Uint8Array(await blob.arrayBuffer());
  return { ciphertext, envelope, contentType };
}
