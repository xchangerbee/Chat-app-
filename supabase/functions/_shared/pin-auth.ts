import { createClient } from "https://esm.sh/@supabase/supabase-js@2.76.1";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

const encoder = new TextEncoder();

async function hmac(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const bytes = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function safeEqual(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const publishableKeysRaw = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS");
  const secretKeysRaw = Deno.env.get("SUPABASE_SECRET_KEYS");
  let publishableDefault = "";
  let secretDefault = "";
  try { publishableDefault = publishableKeysRaw ? JSON.parse(publishableKeysRaw).default ?? "" : ""; } catch { /* handled as missing config */ }
  try { secretDefault = secretKeysRaw ? JSON.parse(secretKeysRaw).default ?? "" : ""; } catch { /* handled as missing config */ }
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? secretDefault;
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ?? publishableDefault;
  const authSecret = Deno.env.get("PIN_AUTH_SECRET");
  const inviteSecret = Deno.env.get("REGISTRATION_INVITE_CODE");
  if (!url || !serviceKey || !anonKey || !authSecret || authSecret.length < 32) {
    return json({ error: "Authentication service is not configured. Contact the app administrator." }, 503);
  }

  let body: { pin?: string; display_name?: string; device_id?: string; invite_code?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid request." }, 400); }
  const pin = body.pin ?? "";
  const deviceId = body.device_id ?? "";
  if (!/^\d{6}$/.test(pin)) return json({ error: "Enter a valid 6-digit PIN." }, 400);
  if (!/^[a-zA-Z0-9-]{16,80}$/.test(deviceId)) return json({ error: "Refresh the page and try again." }, 400);

  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const client = createClient(url, anonKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const action = Deno.env.get("SUPABASE_FUNCTION_NAME") ?? "";
  const path = new URL(req.url).pathname;
  const isRegister = path.endsWith("/register-pin");

  if (isRegister) {
    if (!inviteSecret || !safeEqual(body.invite_code ?? "", inviteSecret)) {
      return json({ error: "Registration is invite-only. Open the invitation link provided by your app administrator." }, 403);
    }
    const name = (body.display_name ?? "").trim();
    if (name.length < 2 || name.length > 40) return json({ error: "Name must be between 2 and 40 characters." }, 400);

    const pinHash = await hmac(authSecret, "pin:" + pin);
    const { data: existing } = await admin.from("pin_credentials").select("user_id").eq("pin_hash", pinHash).maybeSingle();
    if (existing) return json({ error: "That PIN is already taken. Choose another 6-digit PIN." }, 409);

    const userId = crypto.randomUUID();
    const email = "chat-" + userId + "@chat-app.invalid";
    const password = await hmac(authSecret, "auth:" + userId) + "aA9!";
    const { data: created, error: createError } = await admin.auth.admin.createUser({
      id: userId, email, password, email_confirm: true, user_metadata: { display_name: name },
    });
    if (createError || !created.user) return json({ error: "Unable to create the account. Please try again." }, 400);

    const { error: credentialError } = await admin.from("pin_credentials").insert({ user_id: userId, pin_hash: pinHash });
    if (credentialError) {
      await admin.auth.admin.deleteUser(userId);
      if (credentialError.code === "23505") return json({ error: "That PIN is already taken. Choose another 6-digit PIN." }, 409);
      return json({ error: "Unable to save the account securely. Please try again." }, 500);
    }

    const { data: signedIn, error: signInError } = await client.auth.signInWithPassword({ email, password });
    if (signInError || !signedIn.session) return json({ error: "Account created, but sign-in could not complete. Please log in." }, 500);
    const { data: profile } = await admin.from("profiles").select("public_id,display_name").eq("id", userId).maybeSingle();
    return json({ session: signedIn.session, profile });
  }

  const ip = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const clientKey = await hmac(authSecret, "attempt:" + ip + ":" + deviceId);
  const { data: throttle } = await admin.from("pin_login_attempts").select("failed_attempts,locked_until").eq("client_key", clientKey).maybeSingle();
  if (throttle?.locked_until && new Date(throttle.locked_until).getTime() > Date.now()) {
    const seconds = Math.max(1, Math.ceil((new Date(throttle.locked_until).getTime() - Date.now()) / 1000));
    return json({ error: "Too many incorrect PIN attempts. Try again in " + seconds + " seconds.", retry_after: seconds }, 429);
  }

  const pinHash = await hmac(authSecret, "pin:" + pin);
  const { data: credential } = await admin.from("pin_credentials").select("user_id").eq("pin_hash", pinHash).maybeSingle();
  if (!credential) {
    const { data: failed } = await admin.rpc("bump_pin_login_attempt", { p_client_key: clientKey });
    const attempts = Array.isArray(failed) ? failed[0] : failed;
    if (attempts?.locked_until && new Date(attempts.locked_until).getTime() > Date.now()) {
      return json({ error: "Too many incorrect PIN attempts. Try again in 30 seconds.", retry_after: 30 }, 429);
    }
    return json({ error: "Incorrect PIN. Please try again." }, 401);
  }

  const { data: userResult, error: userError } = await admin.auth.admin.getUserById(credential.user_id);
  if (userError || !userResult.user?.email) return json({ error: "Unable to sign in. Contact the app administrator." }, 500);
  const password = await hmac(authSecret, "auth:" + credential.user_id) + "aA9!";
  const { data: signedIn, error: signInError } = await client.auth.signInWithPassword({ email: userResult.user.email, password });
  if (signInError || !signedIn.session) return json({ error: "Unable to sign in securely. Contact the app administrator." }, 500);
  await admin.rpc("reset_pin_login_attempt", { p_client_key: clientKey });
  const { data: profile } = await admin.from("profiles").select("public_id,display_name").eq("id", credential.user_id).maybeSingle();
  return json({ session: signedIn.session, profile });
});
