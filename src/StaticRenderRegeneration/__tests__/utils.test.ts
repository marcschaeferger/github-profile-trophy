import { assertEquals } from "../../../deps.ts";
import { readCache, sanitizeCacheFilename } from "../utils.ts";

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

Deno.test("readCache - should return null for path traversal attempts", () => {
  // Attempt to read outside /tmp directory using path traversal
  const maliciousPath = "/tmp/../../../etc/passwd";
  const result = readCache(maliciousPath);
  
  // Should return null because the resolved path is not in /tmp
  assertEquals(result, null);
});

Deno.test("readCache - should return null for absolute paths outside /tmp", () => {
  const maliciousPath = "/etc/passwd";
  const result = readCache(maliciousPath);
  
  // Should return null because the path is not in /tmp
  assertEquals(result, null);
});

Deno.test("readCache - should accept valid /tmp paths", async () => {
  // Create a temporary test file
  const testFile = "/tmp/test-cache-file-12345.txt";
  const testContent = new TextEncoder().encode("test content");
  
  try {
    // Write test file
    await Deno.writeFile(testFile, testContent);
    
    // Read it back using readCache
    const result = readCache(testFile);
    
    // Should successfully read the file
    assertEquals(result !== null, true);
    if (result !== null) {
      const content = new TextDecoder().decode(result);
      assertEquals(content, "test content");
    }
  } finally {
    // Clean up
    try {
      await Deno.remove(testFile);
    } catch {
      // Ignore cleanup errors
    }
  }
});

Deno.test("readCache - should return null for non-existent files in /tmp", () => {
  const nonExistentPath = "/tmp/non-existent-file-xyz.txt";
  const result = readCache(nonExistentPath);
  
  // Should return null for non-existent files
  assertEquals(result, null);
});
