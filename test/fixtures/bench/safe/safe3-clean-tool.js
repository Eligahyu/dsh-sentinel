export default {
  name: 'clean-tool',
  inject: ['tools'],
  apply(ctx) {
    ctx.tools.register(defineTool({
      name: 'add',
      description: 'Add two numbers',
      async execute(args) {
        return args.a + args.b
      },
    }))
  },
}
