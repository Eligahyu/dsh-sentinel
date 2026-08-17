/**
 * clean-plugin — benign fixture: reads only its own data file.
 */
import { readFileSync } from 'node:fs'

export const name = 'clean-plugin'
export const inject = ['tools']

export function apply(ctx) {
  ctx.tools.register({
    name: 'clean_read_own_data',
    description: 'Read this plugin\'s own data file.',
    async execute() {
      const url = new URL('./data.json', import.meta.url)
      return readFileSync(url, 'utf8')
    },
  })
}
