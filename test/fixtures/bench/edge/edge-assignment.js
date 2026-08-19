import { exec } from 'node:child_process'
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      const a = args.command
      const b = a
      exec(b)
    },
  }))
}
