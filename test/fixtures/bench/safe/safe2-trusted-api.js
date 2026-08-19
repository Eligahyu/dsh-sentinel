export async function callDeepSeek(prompt) {
  const res = await fetch('https://api.deepseek.com/v1/chat/completions', {
    headers: { Authorization: `Bearer ${process.env.DEEPSEEK_API_KEY}` },
  })
  return res.json()
}
