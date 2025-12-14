import { Logger } from "../Helpers/Logger.ts";
import { existsSync, sanitizeCacheFilename } from "./utils.ts";

export class CacheManager {
  private readonly sanitizedCacheFile: string;

  /**
   * Creates a new CacheManager.
   * @param revalidateTime The time in milliseconds to revalidate the cache.
   * @param cacheFile The cache file name to use. This will be sanitized.
   * @throws {Error} If the sanitized cache file name is invalid (empty after sanitization).
   */
  constructor(private revalidateTime: number, private cacheFile: string) {
    // Sanitize the cache filename to prevent path traversal attacks
    this.sanitizedCacheFile = sanitizeCacheFilename(cacheFile);
    if (!this.sanitizedCacheFile) {
      throw new Error(
        `Invalid cacheFile parameter: "${cacheFile}" results in an empty sanitized filename.`
      );
    }
  }

  // Reason to use /tmp/:
  // https://github.com/orgs/vercel/discussions/314
  get cacheFilePath(): string {
    return `/tmp/${this.sanitizedCacheFile}`;
  }
  get cacheFileExists(): boolean {
    return existsSync(this.cacheFilePath);
  }

  get cacheFileLastModified(): Date | null {
    if (!this.cacheFileExists) {
      return null;
    }
    const fileInfo = Deno.statSync(this.cacheFilePath);
    return fileInfo.mtime ?? null;
  }

  get cacheFileLastModifiedGetTime(): number | null {
    const lastModified = this.cacheFileLastModified;
    if (lastModified === null) {
      return null;
    }
    return lastModified.getTime();
  }

  get isCacheValid(): boolean {
    if (this.cacheFileLastModifiedGetTime === null) {
      return false;
    }
    const currentTime = new Date().getTime();
    return currentTime - this.cacheFileLastModifiedGetTime <
      this.revalidateTime;
  }

  async save(response: Response): Promise<void> {
    if (response === null) return;
    // Prevent TypeError: ReadableStream is locked
    const text = await response.clone().text();
    const data = new TextEncoder().encode(text);

    Deno.writeFile(this.cacheFilePath, data, { create: true }).catch(() => {
      Logger.warn("Failed to save cache file");
    });
  }
}
