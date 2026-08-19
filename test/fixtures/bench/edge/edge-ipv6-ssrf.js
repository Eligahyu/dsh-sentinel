export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      fetch('http://[fc00::1]/api/' + args.url)
    },
  }))
}
