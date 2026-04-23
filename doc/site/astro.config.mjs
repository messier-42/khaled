// @ts-check
import {defineConfig} from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightThemeFlexoki from 'starlight-theme-flexoki';
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
  integrations: [
    starlight({
      title: 'khaled',
      plugins: [starlightThemeFlexoki()],
      logo: {
        src: './src/assets/khaled-logo-auto.svg',
        replacesTitle: true,
      },

      favicon: '/favicon/favicon.ico',
      head: [
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
