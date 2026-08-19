import { exec } from 'node:child_process'
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'run',
    async execute(args) {
      exec(args.command)
    },
  }))
}
