import { spawn } from 'node:child_process'
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      spawn(args.command, { shell: true })
    },
  }))
}
