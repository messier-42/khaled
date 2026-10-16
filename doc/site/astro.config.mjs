// @ts-check
import {defineConfig} from 'astro/config';
import starlight from '@astrojs/starlight';
import {releaseInfoRoot} from './src/lib/releases';

const sidebar = [
  {
    label: 'Overview',
    autogenerate: {directory: 'overview'},
  },
  {
    label: 'Plugins',
    autogenerate: {directory: 'plugins'},
  },
  /*  {
      label: 'Installation Guide',
      autogenerate: {directory: 'guides/install'},
    },
    {
      label: 'Operations',
      autogenerate: {directory: 'guides/operations'},
    },
    {
      label: 'Development',
      autogenerate: {directory: 'guides/development'},
    },
    {
      label: 'Examples',
      autogenerate: {directory: 'examples'},
    },*/
  {
    label: 'Reference',
    autogenerate: {directory: 'reference'},
  },
];

if (await releaseInfoRoot() !== null)
  sidebar.push(
    {
      label: 'Releases',
      link: '/releases/',
    });

export default defineConfig({
  site: 'https://khaled.cabespec.org',
  integrations: [
    starlight({
      title: 'khaled',
      description: 'A pluggable reference implementation of a CABE Key Server.',
      customCss: ['./src/styles/cabe.css'],
      components: {
        SocialIcons: './src/components/ProjectLinks.astro',
        Footer: './src/components/DocsFooter.astro',
      },
      expressiveCode: {
        themes: ['github-dark', 'github-light'],
      },
      social: [{icon: 'github', label: 'Khaled on GitHub', href: 'https://github.com/messier-42/khaled'}],
      logo: {
        src: './src/assets/khaled-logo.svg',
        replacesTitle: true,
      },

      favicon: '/favicon/favicon.ico',
      head: [
        {tag: 'meta', attrs: {property: 'og:image', content: 'https://khaled.cabespec.org/social/khaled-preview.png'}},
        {tag: 'meta', attrs: {property: 'og:image:type', content: 'image/png'}},
        {tag: 'meta', attrs: {property: 'og:image:width', content: '1200'}},
        {tag: 'meta', attrs: {property: 'og:image:height', content: '630'}},
        {tag: 'meta', attrs: {property: 'og:image:alt', content: 'Khaled: a pluggable CABE Key Server. Clients obtain key material under an access policy.'}},
        {tag: 'meta', attrs: {name: 'twitter:image', content: 'https://khaled.cabespec.org/social/khaled-preview.png'}},
        {tag: 'meta', attrs: {name: 'twitter:image:alt', content: 'Khaled: a pluggable CABE Key Server. Clients obtain key material under an access policy.'}},
        {
          tag: 'link',
          attrs: {
            rel: 'icon',
            type: 'image/png',
            sizes: '96x96',
            href: '/favicon/favicon-96x96.png',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'icon',
            type: 'image/svg+xml',
            href: '/favicon/favicon.svg',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'apple-touch-icon',
            sizes: '180x180',
            href: '/favicon/apple-touch-icon.png',
          },
        },
      ],

      sidebar,
    }),
  ],
});
