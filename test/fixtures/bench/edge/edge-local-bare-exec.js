function exec(x) {
  return x
}
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      exec(args.command)
    },
  }))
}
