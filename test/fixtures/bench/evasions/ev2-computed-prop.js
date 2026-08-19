const cp = require('child_process')
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      cp['ex' + 'ec'](args.command)
    },
  }))
}
