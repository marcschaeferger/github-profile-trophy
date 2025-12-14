import { assertEquals } from "../../../deps.ts";
import { CacheManager } from "../cache_manager.ts";

Deno.test("CacheManager - should sanitize cache file path", () => {
  const maliciousPath = "../../../etc/passwd";
  const manager = new CacheManager(1000, maliciousPath);

  // The path should be sanitized and not allow directory traversal
  const expectedPath = "/tmp/etcpasswd";
  assertEquals(manager.cacheFilePath, expectedPath);
});

Deno.test("CacheManager - should accept valid hash as cache file", () => {
  const validHash =
    "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890";
  const manager = new CacheManager(1000, validHash);

  const expectedPath = `/tmp/${validHash}`;
  assertEquals(manager.cacheFilePath, expectedPath);
});

Deno.test("CacheManager - should prevent path traversal with encoded characters", () => {
  const encodedPath = "..%2F..%2Froot%2F.ssh%2Fid_rsa";
  const manager = new CacheManager(1000, encodedPath);

  // Should remove all special characters except underscores and alphanumeric
  const expectedPath = "/tmp/2F2Froot2Fssh2Fid_rsa";
  assertEquals(manager.cacheFilePath, expectedPath);
});

Deno.test("CacheManager - should prevent absolute path injection", () => {
  const absolutePath = "/etc/passwd";
  const manager = new CacheManager(1000, absolutePath);

  const expectedPath = "/tmp/etcpasswd";
  assertEquals(manager.cacheFilePath, expectedPath);
});

Deno.test("CacheManager - should handle cache file with slashes", () => {
  const pathWithSlashes = "cache/path/file";
  const manager = new CacheManager(1000, pathWithSlashes);

  const expectedPath = "/tmp/cachepathfile";
  assertEquals(manager.cacheFilePath, expectedPath);
});
