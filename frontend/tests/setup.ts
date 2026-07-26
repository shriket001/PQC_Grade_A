import "@testing-library/jest-dom/vitest";

// jsdom's Blob (and File, which extends it) implementation doesn't provide
// `arrayBuffer()` — every real browser has supported it for years, and US4's
// file-sharing code (`fileService.downloadFile`, `messagingStore.sendFile`)
// relies on it to read encrypted file bytes. Polyfill it for the test
// environment only; production code never needs this shim.
if (typeof Blob !== "undefined" && !Blob.prototype.arrayBuffer) {
  Blob.prototype.arrayBuffer = function arrayBuffer(this: Blob): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as ArrayBuffer);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(this);
    });
  };
}
