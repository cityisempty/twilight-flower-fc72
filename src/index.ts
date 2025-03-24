import type { Request } from '@cloudflare/workers-types';

export interface Env {
  DB: D1Database;
}

export default {
  async fetch(request: Request, env: Env) {
    if (request.method !== "POST") {
      return new Response("请使用POST方法触发卡密生成", { status: 405 });
    }
    
    try {
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS card_keys (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key_code TEXT UNIQUE NOT NULL,
          first_used_at TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          is_used INTEGER DEFAULT 0
        )
      `).run();
      
      const keyCount = 100000;
      let insertedCount = 0;
      const batchSize = 1000;
      
      for (let batch = 0; batch < keyCount / batchSize; batch++) {
        const stmt = env.DB.prepare(`INSERT INTO card_keys (key_code) VALUES (?)`);
        const batch_inserts = [];
        
        for (let i = 0; i < batchSize; i++) {
          const keyCode = generateCardKey();
          batch_inserts.push(stmt.bind(keyCode));
        }
        
        const results = await env.DB.batch(batch_inserts);
        insertedCount += results.length;
      }
      
      return new Response(`成功生成并插入了${insertedCount}个卡密`, {
        headers: { "Content-Type": "text/plain" }
      });
    } catch (error) {
          return new Response(`生成卡密时出错: ${(error as Error).message}`, { 
        status: 500,
        headers: { "Content-Type": "text/plain" }
      });
    }
  }
};

function generateCardKey() {
  const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let result = '';
  
  for (let group = 0; group < 5; group++) {
    for (let i = 0; i < 5; i++) {
      const randomIndex = Math.floor(Math.random() * chars.length);
      result += chars[randomIndex];
    }
    
    if (group < 4) {
      result += '-';
    }
  }
  
  return result;
}
