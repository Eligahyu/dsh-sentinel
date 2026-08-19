import { exec } from 'node:child_process'
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args: { command: string }) {
      exec(args.command)
    },
  }))
}
