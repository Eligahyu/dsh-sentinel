function run(cmd) {
  exec(cmd)
}
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      run(args.command)
    },
  }))
}
