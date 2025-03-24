// functions/api/verify-password.js
import { z } from 'zod';

const CardValidationSchema = z.object({
  cardKey: z.string().length(16).regex(/^[A-Z0-9]+$/)
});

export async function onRequest({ request, env }: { request: Request; env: { DB: D1Database } }) {
  if (request.method !== "POST") {
    return new Response("请使用POST方法", { status: 405 });
  }
  
  try {
    const data = await request.json();
    const { cardKey } = CardValidationSchema.parse(data);
    
    const db = env.DB;
interface CardKey {
  card_key: string;
  expires_at: number;
  is_used: boolean;
  activated_at?: number;
}

    const result = await db.prepare(
      `SELECT * FROM card_keys 
       WHERE card_key = ? 
       AND expires_at > strftime('%s', 'now')`
    ).bind(cardKey).first<CardKey>();

    if (!result) {
      return Response.json({ 
        valid: false, 
        code: 'INVALID_CARD',
        message: "卡密无效或已过期" 
      });
    }

    const now = Math.floor(Date.now() / 1000);
    let sessionToken = null;

    if (result.is_used) {
      if (now > result.expires_at) {
        return Response.json({
          valid: false,
          code: 'CARD_EXPIRED',
          message: "卡密已过期"
        });
      }
      
      // 生成短期会话（剩余时间）
      const remainingTime = result.expires_at - now;
      sessionToken = crypto.randomUUID();
      
      return new Response(JSON.stringify({ 
        valid: true,
        code: 'SESSION_RENEWED',
        expires_in: remainingTime
      }), {
        headers: { 
          "Content-Type": "application/json",
          "Set-Cookie": `session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${remainingTime}`
        }
      });
    }

    // 首次激活
    sessionToken = crypto.randomUUID();
    await db.prepare(
      `UPDATE card_keys 
       SET is_used = TRUE, 
           activated_at = ?,
           expires_at = ? 
       WHERE card_key = ?`
    ).bind(now, now + (24 * 60 * 60), cardKey) // 30天有效期
    .run();

    return new Response(JSON.stringify({ 
      valid: true,
      code: 'ACTIVATION_SUCCESS',
      expires_in: 2592000 // 30天秒数
    }), {
      headers: { 
        "Content-Type": "application/json",
        "Set-Cookie": `session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`
      }
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      return Response.json({
        valid: false,
        code: 'INVALID_INPUT',
        message: "卡密格式错误（必须为16位大写字母和数字）"
      }, { status: 400 });
    }
    return Response.json({ 
      valid: false,
      code: 'SERVER_ERROR',
      message: "验证过程中发生错误" 
    }, { status: 500 });
  }
}

async function sha256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
