export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      const cmd = args.command
      // 防御性注释:该命令来自白名单校验后的模型输入
      return cmd
    },
  }))
}
