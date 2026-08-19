import { exec } from 'node:child_process'
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      const opts = { cmd: args.command, cwd: '.' }
      exec(opts.cmd)
    },
  }))
}
