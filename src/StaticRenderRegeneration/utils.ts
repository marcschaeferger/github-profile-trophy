import { resolve } from "https://deno.land/std@0.203.0/path/mod.ts";

export function getUrl(request: Request) {
  try {
    return new URL(request.url);
  } catch {
    return {
      pathname: request.url,
      search: request.url,
    };
  }
}

/**
 * Reads cache file from disk.
 * 
 * SECURITY: This function includes path traversal protection by:
 * 1. Normalizing the path to resolve .. and . sequences
 * 2. Validating that the resolved path is within /tmp directory
 * 
 * NOTE: This validation is designed for Unix-like systems (Linux, macOS)
 * which use case-sensitive filesystems and forward slashes.
 * The application runs on Vercel/Docker Linux environments.
 * 
 * @param cacheFilePath - Path to the cache file
 * @returns File contents as Uint8Array, or null if file cannot be read
 */
export function readCache(cacheFilePath: string): Uint8Array | null {
  try {
    // Resolve the path to normalize any .. or . sequences
    // This prevents path traversal attacks like /tmp/../../../etc/passwd
    const resolvedPath = resolve(cacheFilePath);
    
    // Ensure the path is within the /tmp directory to prevent path traversal
    // Check if path is exactly /tmp or starts with /tmp/
    const resolvedPathLower = resolvedPath.toLowerCase();
    if (resolvedPathLower !== "/tmp" && !resolvedPathLower.startsWith("/tmp/")) {
      throw new Error("Access denied: Cache files must be in /tmp directory");
    }
    
    return Deno.readFileSync(resolvedPath);
  } catch {
    return null;
  }
}

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
export async function hashString(message: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);

  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join(
    "",
  );

  return hashHex;
}

export const existsSync = (filename: string): boolean => {
  try {
    Deno.statSync(filename);
    // successful, file or directory must exist
    return true;
  } catch {
    return false;
  }
};

/**
 * Sanitizes a cache filename to prevent path traversal attacks.
 * Only allows alphanumeric characters, hyphens, and underscores.
 * Removes any path separators and relative path sequences.
 * @param filename - The filename to sanitize
 * @returns Sanitized filename safe for use in file paths
 */
export function sanitizeCacheFilename(filename: string): string {
  // Remove any path separators and parent directory references
  // Only allow alphanumeric characters, hyphens, and underscores
  const sanitized = filename.replace(/[^a-zA-Z0-9_-]/g, "");

  // Ensure the result is not empty
  if (sanitized.length === 0) {
    throw new Error(
      "Invalid cache filename: sanitization resulted in empty string",
    );
  }

  return sanitized;
}
