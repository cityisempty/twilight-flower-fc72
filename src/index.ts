import { z } from 'zod';

const CardValidationSchema = z.object({
  cardKey: z.string().regex(/^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/, 
    "卡密格式错误，正确格式应为：XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
});

interface CardKey {
  card_key: string;
  expires_at: number;
  is_used: boolean;
  activated_at?: number;
}

export interface Env {
  DB: D1Database;
}
// 修改 CORS 配置，使用更具体的源
const corsHeaders = {
  "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Credentials": "true",
}

function handleOptions(request) {
  // 使用请求中的 Origin
  const origin = request.headers.get("Origin") || "*";
  
  if (request.headers.get("Origin") !== null &&
    request.headers.get("Access-Control-Request-Method") !== null &&
    request.headers.get("Access-Control-Request-Headers") !== null) {
    // Handle CORS pre-flight request.
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || "Content-Type",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Max-Age": "86400",
      }
    })
  } else {
    // Handle standard OPTIONS request.
    return new Response(null, {
      headers: {
        "Allow": "POST, OPTIONS",
        "Access-Control-Allow-Origin": origin,
      }
    })
  }
}

export default {
  async fetch(request: Request, env: Env) {
    // 获取请求的 Origin
    const origin = request.headers.get("Origin") || "*";
    // 更新 corsHeaders 以使用动态 Origin
    const corsHeaders = {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Credentials": "true",
    };
    
    if (request.method === "OPTIONS") {
      return handleOptions(request);
    }
    
    if (request.method !== "POST") {
      return new Response("请使用POST方法", { 
        status: 405,
        headers: corsHeaders
      });
    }
    
    try {
      const data = await request.json();
      const { cardKey } = CardValidationSchema.parse(data);
      
      const db = env.DB;

      // 添加更多调试信息
      console.log(`正在验证卡密: ${cardKey}`);

      // 使用数据库时间函数进行查询
      const result = await db.prepare(
        `SELECT *, 
                (first_used_at + ${24 * 60 * 60}) as expires_at 
         FROM card_keys 
         WHERE key_code = ? 
         AND (first_used_at IS NULL OR first_used_at + ${24 * 60 * 60} - strftime('%s', 'now'))>0`
      ).bind(cardKey).first<CardKey>();

      if (!result) {
        console.log(`卡密验证失败: ${cardKey} - 无效或已过期`);
        return new Response(JSON.stringify({
          valid: false,
          code: 'INVALID_CARD',
          message: "卡密无效或已过期"
        }), {
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders,
          }
        })
      }

      // 获取当前时间戳
      const currentTimeResult = await db.prepare("SELECT strftime('%s', 'now') as current_time").first<{current_time: string}>();
      const now = parseInt(currentTimeResult?.current_time || '0', 10);
      
      let sessionToken = null;
      
      if (result.is_used) {
        // 计算过期时间 = 首次使用时间 + 24小时
        const expiresAt = result.first_used_at + (24 * 60 * 60);
        
        if (now > expiresAt) {
          console.log(`卡密已过期: ${cardKey}, 过期时间: ${new Date(expiresAt * 1000).toISOString()}`);
          return new Response(JSON.stringify({
            valid: false,
            code: 'CARD_EXPIRED',
            message: "卡密已过期"
          }), {
            headers: {
              "Content-Type": "application/json",
              ...corsHeaders,
            }
          })
        }
        
        // 生成短期会话（剩余时间）
        const remainingTime = expiresAt - now;
        sessionToken = crypto.randomUUID();
        
        console.log(`续期会话: ${cardKey}, 剩余时间: ${remainingTime}秒`);
        return new Response(JSON.stringify({ 
          valid: true,
          code: 'SESSION_RENEWED',
          expires_in: remainingTime
        }), {
          headers: { 
            "Content-Type": "application/json",
            "Set-Cookie": `session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${remainingTime}`,
            ...corsHeaders,
          }
        });
      }

      // 首次激活 - 设置为24小时有效期
      const expiresIn = 24 * 60 * 60; // 24小时的秒数
      sessionToken = crypto.randomUUID();
      
      console.log(`首次激活卡密: ${cardKey}, 有效期至: ${new Date((now + expiresIn) * 1000).toISOString()}`);
      
      await db.prepare(
        `UPDATE card_keys 
         SET is_used = 1, 
             first_used_at = strftime('%s', 'now')
         WHERE key_code = ?`
      ).bind(cardKey) // 使用数据库时间函数
      .run();

      return new Response(JSON.stringify({ 
        valid: true,
        code: 'ACTIVATION_SUCCESS',
        expires_in: expiresIn // 24小时秒数
      }), {
        headers: { 
          "Content-Type": "application/json",
          "Set-Cookie": `session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${expiresIn}`,
          ...corsHeaders,
        }
      });

    } catch (error) {
      if (error instanceof z.ZodError) {
        const errorDetails = error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join('; ');
        console.error(`输入验证错误: ${errorDetails}`);
        return new Response(JSON.stringify({
          valid: false,
          code: 'INVALID_INPUT',
          message:`卡密格式错误: ${errorDetails}`
        }), {
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders,
          }
        })
      }
      
      console.error(`服务器错误: ${error instanceof Error ? error.message : String(error)}`);
      console.error(`错误详情: ${error instanceof Error && error.stack ? error.stack : '无堆栈信息'}`);
      return new Response(JSON.stringify({
        valid: false,
        code: 'SERVER_ERROR',
        message:`验证过程中发生错误: ${error instanceof Error ? error.message : String(error)}` 
      }), {
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders,
        }
      });
    }
  }
};

async function sha256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
