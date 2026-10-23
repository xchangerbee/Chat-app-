# Chat

A private, mobile-first one-to-one team chat app built with Next.js, TypeScript, Tailwind CSS, and Supabase.

## Current foundation
- Responsive authentication and chat dashboard UI.
- PIN-only login/register Edge Functions with HMAC-derived PIN verification, hidden Supabase Auth identities, and persistent server-side 3-attempt / 30-second cooldown.
- Four-digit public IDs and a database RPC for opening or reusing a one-to-one conversation.
- RLS policies on app tables; server-only PIN credential tables are not accessible to anon/authenticated clients.
- Message schema stores ciphertext and nonce fields; actual end-to-end encryption is not implemented yet and message sending remains disabled.

## Local setup
1. Install Node.js 20.9+.
2. Copy .env.example to .env.local and set your Supabase project URL and publishable/anon key.
3. Run npm install and npm run dev.

## Required Supabase Edge Function secrets
In Supabase Dashboard → Edge Functions → Secrets, configure:
- PIN_AUTH_SECRET: a cryptographically random secret with at least 32 characters. Keep it stable; changing it without a planned migration will prevent existing PIN accounts from signing in.
- REGISTRATION_INVITE_CODE: a strong invitation token. Registration is invite-only. Share a link like https://YOUR-APP-DOMAIN/?invite=YOUR_INVITE_TOKEN with trusted teammates, then rotate the invite code after onboarding.

Do not paste these secrets into chat, GitHub, browser code, or the Vercel frontend environment. Supabase's built-in service-role key must remain server-side.

## Security status
This is an in-progress foundation, not yet production-ready for sensitive conversations. Before using it for private messages, implement and independently test end-to-end encryption with a maintained protocol, encrypted key backup/recovery decisions, message delivery/seen updates, session lifecycle, and full abuse/rate-limit testing. Do not store plaintext message content. PIN-only login is intentionally a limited-team convenience, not strong multi-factor authentication.
