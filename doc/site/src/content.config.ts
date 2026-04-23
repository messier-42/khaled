import {defineCollection, z} from 'astro:content';
import type {Loader} from 'astro/loaders';
import {docsLoader} from '@astrojs/starlight/loaders';
import {docsSchema} from '@astrojs/starlight/schema';
import {releaseInfoRoot} from './lib/releases';
import fs from 'node:fs/promises';
import path from 'node:path';

const ReleaseData = z.object({
  tag_name: z.string(),
  published_at: z.string(),
  rendered_body: z.string(),
  body: z.string().optional(),
});

export function releasesLoader(settings): Loader {
  return {
    name: 'releases-loader',
    schema: async () => ReleaseData,
    async load({renderMarkdown, store}) {
      store.clear();

      const releaseInfoPath = await releaseInfoRoot();
      if (releaseInfoPath == null)
        return;

      console.log('RIP', releaseInfoPath);
      const releaseSummariesPath = path.join(releaseInfoPath, 'releases.json');
      let releaseSummariesUnparsed;
      try {
        releaseSummariesUnparsed = await fs.readFile(releaseSummariesPath, 'utf8');
      } catch (e) {
        return;
      }

      const releaseSummaries = JSON.parse(releaseSummariesUnparsed) as any[];

      const entries = await Promise.all(
        releaseSummaries.map(async (s) => {
          const tagName = s.tag_name;
          const releaseDetailPath = path.join(releaseInfoPath, tagName + '.json');
          const releaseDetailUnparsed = await fs.readFile(releaseDetailPath, 'utf8');
          const releaseDetail = JSON.parse(releaseDetailUnparsed) as any[];
          if (!releaseDetail.body)
            releaseDetail.body = '';

          const entry = {
            data: releaseDetail,

            id: releaseDetail.tag_name,
            body: releaseDetail.body,
            rendered: await renderMarkdown(releaseDetail.body),
          };

          return entry;
        }));

      for (const e of entries)
        store.set(e);
    },
  };
}

export const collections = {
  docs: defineCollection({loader: docsLoader(), schema: docsSchema()}),

  releases: defineCollection({
    loader: releasesLoader({}),
  }),
};
