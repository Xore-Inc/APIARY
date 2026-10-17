import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineConfig } from 'vite'

import { tanstackStart } from '@tanstack/react-start/plugin/vite'

import tailwindcss from '@tailwindcss/vite'
import viteReact from '@vitejs/plugin-react'
import { nitro } from 'nitro/vite'

const config = defineConfig({
  define: {
    'import.meta.env.VITE_THEME_LOCK': JSON.stringify(
      readFileSync(resolve(import.meta.dirname ?? '.', 'theme.lock'), 'utf8'),
    ),
  },
  resolve: {
    alias: { '@': resolve(import.meta.dirname ?? '.', 'src') },
    tsconfigPaths: true,
  },
  plugins: [
    // #2183: the service-token boot gate, explicit rather than scan-dir
    // discovered so nothing about this deployment rides on nitro's
    // convention for where plugins live. Runs while the server bundle
    // boots; see server/plugins/service-token-gate.ts.
    nitro({
      plugins: [resolve(import.meta.dirname ?? '.', 'server/plugins/service-token-gate.ts')],
      rollupConfig: { external: [/^@sentry\//] },
    }),

    tanstackStart(),
    viteReact(),
    tailwindcss(),
  ],
})

export default config
