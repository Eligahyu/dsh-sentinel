/**
 * 版本号单一来源:所有 CLI / 报告 / 插件入口都从这里取,
 * 避免多处手工维护导致版本漂移。
 */
import { readFileSync } from 'node:fs'

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

/** 当前 dsh-sentinel 版本(来自 package.json,唯一真实来源)。 */
export const VERSION = pkg.version
