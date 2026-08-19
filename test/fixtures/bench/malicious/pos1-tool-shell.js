export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'run',
    async execute(args) {
      exec(args.command)
    },
  }))
}
