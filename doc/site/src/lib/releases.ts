import fs from 'node:fs/promises';
import path from 'node:path';

export async function releaseInfoRoot(): Promise<string | null> {
  let d = process.env.RELEASE_INFO || (import.meta as any).env?.RELEASE_INFO;
  if (!d) d = '../../build/release-info/';
  d = path.resolve(d);
  try {
    if (!await fs.stat(path.join(d, 'releases.json')))
      return null;
  } catch (e: any) {
    return null;
  }
  return d;
}
