import { assertEquals } from "../../../deps.ts";
import { sanitizeCacheFilename } from "../utils.ts";

Deno.test("sanitizeCacheFilename - should allow valid hex hash", () => {
  const validHash =
    "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890";
  const result = sanitizeCacheFilename(validHash);
  assertEquals(result, validHash);
});

Deno.test("sanitizeCacheFilename - should allow alphanumeric with hyphens and underscores", () => {
  const validName = "cache-file_123";
  const result = sanitizeCacheFilename(validName);
  assertEquals(result, validName);
});

Deno.test("sanitizeCacheFilename - should remove path traversal sequences", () => {
  const maliciousPath = "../../../etc/passwd";
  const result = sanitizeCacheFilename(maliciousPath);
  assertEquals(result, "etcpasswd");
});

Deno.test("sanitizeCacheFilename - should remove forward slashes", () => {
  const pathWithSlash = "path/to/file";
  const result = sanitizeCacheFilename(pathWithSlash);
  assertEquals(result, "pathtofile");
});

Deno.test("sanitizeCacheFilename - should remove backslashes", () => {
  const pathWithBackslash = "path\\to\\file";
  const result = sanitizeCacheFilename(pathWithBackslash);
  assertEquals(result, "pathtofile");
});

Deno.test("sanitizeCacheFilename - should remove null bytes", () => {
  const pathWithNull = "file\x00name";
  const result = sanitizeCacheFilename(pathWithNull);
  assertEquals(result, "filename");
});

Deno.test("sanitizeCacheFilename - should remove special characters", () => {
  const pathWithSpecial = "file@#$%^&*()name";
  const result = sanitizeCacheFilename(pathWithSpecial);
  assertEquals(result, "filename");
});

Deno.test("sanitizeCacheFilename - should throw error for empty result", () => {
  let error = null;
  try {
    sanitizeCacheFilename("@#$%^&*()");
  } catch (e) {
    error = e;
  }

  assertEquals(error instanceof Error, true);
  assertEquals(
    (error as Error).message,
    "Invalid cache filename: sanitization resulted in empty string",
  );
});

Deno.test("sanitizeCacheFilename - should handle absolute paths", () => {
  const absolutePath = "/tmp/cache/file";
  const result = sanitizeCacheFilename(absolutePath);
  assertEquals(result, "tmpcachefile");
});

Deno.test("sanitizeCacheFilename - should prevent directory escape attempts", () => {
  const escapeAttempt = "..%2F..%2Fetc%2Fpasswd";
  const result = sanitizeCacheFilename(escapeAttempt);
  assertEquals(result, "2F2Fetc2Fpasswd");
});
