import { spawn } from 'node:child_process'
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'gitStatus',
    async execute() {
      spawn('git', ['status'])
    },
  }))
}
