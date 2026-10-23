"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, ChevronDown, LockKeyhole, LogOut, MessageCircle, MoreHorizontal, Plus, Search, Settings, ShieldCheck, Sparkles, Users, Sun, Moon } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

type Mode = "login" | "register";
type Profile = { id: string; public_id: string; display_name: string };
type ChatItem = { id: string; other: Profile; last_message_at: string };
type SupabaseClient = NonNullable<ReturnType<typeof createClient>>;


function bytesToB64(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary);
}
function b64ToBytes(value: string) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}
async function ensureDeviceKey(client: SupabaseClient, userId: string) {
  // Keep each account's private key separate on shared browsers.
  const storageKey = "chat_private_key_v1:" + userId;
  let privateKeyBytes: Uint8Array;
  let publicKeyB64: string;
  const saved = window.localStorage.getItem(storageKey);
  if (saved) {
    const parsed = JSON.parse(saved);
    privateKeyBytes = b64ToBytes(parsed.privateKey);
    publicKeyB64 = parsed.publicKey;
  } else {
    const pair = await window.crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
    privateKeyBytes = new Uint8Array(await window.crypto.subtle.exportKey("pkcs8", pair.privateKey));
    publicKeyB64 = bytesToB64(new Uint8Array(await window.crypto.subtle.exportKey("spki", pair.publicKey)));
    window.localStorage.setItem(storageKey, JSON.stringify({ privateKey: bytesToB64(privateKeyBytes), publicKey: publicKeyB64 }));
  }
  const { data: existing, error: lookupError } = await client.from("devices").select("id").eq("user_id", userId).eq("identity_public_key", publicKeyB64).is("revoked_at", null).maybeSingle();
  if (lookupError) throw lookupError;
  let deviceId = existing?.id as string | undefined;
  if (!deviceId) {
    const { data: created, error } = await client.from("devices").insert({ user_id: userId, device_label: "This browser", identity_public_key: publicKeyB64 }).select("id").single();
    if (error) throw error;
    deviceId = created.id as string;
  }
  const privateKeyBuffer = Uint8Array.from(privateKeyBytes).buffer;
  const privateKey = await window.crypto.subtle.importKey("pkcs8", privateKeyBuffer, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  return { privateKey, publicKeyB64, deviceId };
}
async function encryptMessage(client: SupabaseClient, userId: string, recipientId: string, text: string) {
  const { deviceId: ownDeviceId, publicKeyB64: ownPublicKey } = await ensureDeviceKey(client, userId);
  const { data: devices, error } = await client.from("devices").select("id,user_id,identity_public_key").in("user_id", [userId, recipientId]).is("revoked_at", null);
  if (error) throw error;
  const targets = new Map<string, { user_id: string; identity_public_key: string }>();
  for (const device of (devices || [])) targets.set(device.id, device);
  // Ensure this browser's current public key is the key used for this account/device.
  targets.set(ownDeviceId, { user_id: userId, identity_public_key: ownPublicKey });
  if (![...targets.values()].some(device => device.user_id === recipientId)) throw new Error("Your teammate needs to open the app once to set up secure messaging.");
  const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const body = new Uint8Array(await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(text)));
  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
  const wrapped: Record<string, string> = {};
  for (const [deviceId, device] of targets) {
    const publicKey = await window.crypto.subtle.importKey("spki", b64ToBytes(device.identity_public_key), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    wrapped[deviceId] = bytesToB64(new Uint8Array(await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawAesKey)));
  }
  return { ciphertext: JSON.stringify({ v: 2, body: bytesToB64(body), keys: wrapped }), nonce: bytesToB64(iv) };
}
async function decryptMessage(client: SupabaseClient, userId: string, ciphertext: string, nonce: string) {
  try {
    const packet = JSON.parse(ciphertext) as { v: number; body: string; keys: Record<string, string> };
    const { privateKey, deviceId } = await ensureDeviceKey(client, userId);
    // v1 messages used user IDs as recipient keys; v2 uses unique device IDs.
    const wrappedKey = packet.v === 1 ? packet.keys?.[userId] : packet.v === 2 ? packet.keys?.[deviceId] : undefined;
    if (!wrappedKey) return "[This message isn't available on this device]";
    const rawKey = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, b64ToBytes(wrappedKey));
    const aesKey = await window.crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
    const plain = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(nonce) }, aesKey, b64ToBytes(packet.body));
    return new TextDecoder().decode(plain);
  } catch {
    return "This message isn’t available on this device.";
  }
}
type MessageItem = { id: string; conversation_id: string; sender_id: string; ciphertext: string; nonce: string; created_at: string; text?: string };

function getDeviceId() {
  if (typeof window === "undefined") return "server-render-device-id";
  const key = "chat_device_id";
  let id = window.localStorage.getItem(key);
  if (!id) { id = window.crypto.randomUUID(); window.localStorage.setItem(key, id); }
  return id;
}

export default function Home() {
  const [mode, setMode] = useState<Mode>("login");
  const [displayName, setDisplayName] = useState("");
  const [pin, setPin] = useState("");
  const [inviteCode, setInviteCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [lockoutSeconds, setLockoutSeconds] = useState(0);
  const [notice, setNotice] = useState("");
  const [isError, setIsError] = useState(false);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [chats, setChats] = useState<ChatItem[]>([]);
  const [search, setSearch] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [userIdCopied, setUserIdCopied] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark">("light");
  const [selectedChat, setSelectedChat] = useState<ChatItem | null>(null);
  const [mobileChatOpen, setMobileChatOpen] = useState(false);
  const [searching, setSearching] = useState(false);
  const [searchNotice, setSearchNotice] = useState("");
  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const settingsOpenRef = useRef(settingsOpen);
  const mobileChatOpenRef = useRef(mobileChatOpen);

  settingsOpenRef.current = settingsOpen;
  mobileChatOpenRef.current = mobileChatOpen;

  const supabase = useMemo(() => createClient(), []);

  useEffect(() => {
    if (lockoutSeconds <= 0) return;
    const timerId = window.setInterval(() => {
      setLockoutSeconds(seconds => Math.max(0, seconds - 1));
    }, 1000);
    return () => window.clearInterval(timerId);
  }, [lockoutSeconds > 0]);

  useEffect(() => {
    try {
      const savedTheme = window.localStorage.getItem("chat_theme");
      if (savedTheme === "dark" || savedTheme === "light") setTheme(savedTheme);
    } catch {
      // Keep the default light theme if browser storage is unavailable.
    }
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    const themeColor = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
    if (themeColor) themeColor.content = theme === "dark" ? "#111725" : "#f7f8fc";
    try {
      window.localStorage.setItem("chat_theme", theme);
    } catch {
      // Theme still applies for the current session if storage is unavailable.
    }
  }, [theme]);

  useEffect(() => {
    // Let Android/browser Back close the most recently opened in-app view first.
    // Keep this scoped to the signed-in app so auth/navigation behavior is untouched.
    const handleAppBack = () => {
      if (settingsOpenRef.current) {
        settingsOpenRef.current = false;
        setSettingsOpen(false);
        if (mobileChatOpenRef.current) window.history.pushState({ chatAppView: "chat" }, "", window.location.href);
        return;
      }
      if (mobileChatOpenRef.current) {
        mobileChatOpenRef.current = false;
        setMobileChatOpen(false);
        setSelectedChat(null);
      }
    };
    window.addEventListener("popstate", handleAppBack);
    return () => window.removeEventListener("popstate", handleAppBack);
  }, []);

  useEffect(() => {
    if (!settingsOpen) return;
    const closeSettingsOnOutsidePress = (event: PointerEvent) => {
      const target = event.target;
      if (target instanceof Element && !target.closest(".side-bottom")) setSettingsOpen(false);
    };
    document.addEventListener("pointerdown", closeSettingsOnOutsidePress);
    return () => document.removeEventListener("pointerdown", closeSettingsOnOutsidePress);
  }, [settingsOpen]);

  useEffect(() => {
    if (!searchNotice) return;
    const timeoutId = window.setTimeout(() => setSearchNotice(""), 3500);
    return () => window.clearTimeout(timeoutId);
  }, [searchNotice]);

  useEffect(() => {
    // Track the visible mobile viewport so the chat stays above the Android
    // on-screen keyboard instead of relying on sticky positioning alone.
    const viewport = window.visualViewport;
    const updateChatViewport = () => {
      const height = viewport?.height ?? window.innerHeight;
      const offsetTop = viewport?.offsetTop ?? 0;
      document.documentElement.style.setProperty("--chat-viewport-height", height + "px");
      document.documentElement.style.setProperty("--chat-viewport-offset-top", offsetTop + "px");
    };
    updateChatViewport();
    viewport?.addEventListener("resize", updateChatViewport);
    viewport?.addEventListener("scroll", updateChatViewport);
    window.addEventListener("resize", updateChatViewport);
    window.addEventListener("orientationchange", updateChatViewport);
    return () => {
      viewport?.removeEventListener("resize", updateChatViewport);
      viewport?.removeEventListener("scroll", updateChatViewport);
      window.removeEventListener("resize", updateChatViewport);
      window.removeEventListener("orientationchange", updateChatViewport);
      document.documentElement.style.removeProperty("--chat-viewport-height");
      document.documentElement.style.removeProperty("--chat-viewport-offset-top");
    };
  }, []);

  useEffect(() => {
    if (!supabase) return;
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) void loadProfile(data.session.user.id);
    });
    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) void loadProfile(session.user.id);
      else { setProfile(null); setChats([]); setSelectedChat(null); }
    });
    return () => listener.subscription.unsubscribe();
    // Supabase client is stable for this page lifecycle.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadProfile(userId: string) {
    if (!supabase) return;
    const { data } = await supabase.from("profiles").select("id,public_id,display_name").eq("id", userId).maybeSingle();
    if (data) { setProfile(data as Profile); await loadChats(userId); try { await ensureDeviceKey(supabase, userId); } catch (e) { console.error("Secure device setup failed", e); } }
  }

  async function loadChats(userId: string) {
    if (!supabase) return;

    // Fetch only conversations this signed-in user belongs to.
    const { data: memberships, error: membershipsError } = await supabase
      .from("conversation_members")
      .select("conversation_id,joined_at")
      .eq("user_id", userId)
      .order("joined_at", { ascending: false });

    if (membershipsError) {
      console.error("Conversation list load failed:", membershipsError);
      setNotice("Couldn't load your conversation list. Please refresh and try again.");
      setIsError(true);
      return;
    }

    if (!memberships?.length) {
      setChats([]);
      return;
    }

    const result: ChatItem[] = [];
    for (const membership of memberships) {
      const { data: members, error: membersError } = await supabase
        .from("conversation_members")
        .select("user_id")
        .eq("conversation_id", membership.conversation_id);

      if (membersError) {
        console.error("Conversation participants load failed:", membersError);
        continue;
      }

      // conversation_members.user_id references auth.users, not profiles.
      // Resolve participant profiles with a separate query instead of a nonexistent nested relationship.
      const participantIds = [...new Set((members || []).map((member) => member.user_id).filter((id) => id !== userId))];
      if (!participantIds.length) continue;

      const { data: profiles, error: profilesError } = await supabase
        .from("profiles")
        .select("id,public_id,display_name")
        .in("id", participantIds);

      if (profilesError) {
        console.error("Conversation profiles load failed:", profilesError);
        continue;
      }

      const other = (profiles || []).find((participant) => participant.id !== userId);

      const { data: conversation, error: conversationError } = await supabase
        .from("conversations")
        .select("id,last_message_at")
        .eq("id", membership.conversation_id)
        .maybeSingle();

      if (conversationError) {
        console.error("Conversation details load failed:", conversationError);
        continue;
      }

      if (other && conversation) {
        result.push({
          id: conversation.id,
          other: other as Profile,
          last_message_at: conversation.last_message_at || membership.joined_at,
        });
      }
    }

    result.sort((a, b) => new Date(b.last_message_at).getTime() - new Date(a.last_message_at).getTime());
    setChats(result);
  }

  async function copyUserId() {
    if (!profile?.public_id) return;
    try {
      await navigator.clipboard.writeText(profile.public_id);
      setUserIdCopied(true);
      window.setTimeout(() => setUserIdCopied(false), 1800);
    } catch {
      setNotice("Couldn’t copy your ID. Please try again.");
      setIsError(true);
    }
  }

  async function submitAuth(e: React.FormEvent) {
    e.preventDefault();
    if (mode === "login" && lockoutSeconds > 0) return;
    setNotice(""); setIsError(false);
    if (mode === "register" && displayName.trim().length < 2) { setNotice("Please enter a name with at least 2 characters."); setIsError(true); return; }
    if (mode === "register" && !inviteCode.trim() && !new URLSearchParams(window.location.search).get("invite")) { setNotice("Enter your team invitation code to register."); setIsError(true); return; }
    if (!/^\d{6}$/.test(pin)) { setNotice("Enter your 6-digit PIN."); setIsError(true); return; }
    if (!supabase) { setNotice("We can’t connect right now. Please try again in a little while."); setIsError(true); return; }
    setBusy(true);
    try {
      const device_id = getDeviceId();
      const invite_code = inviteCode.trim() || new URLSearchParams(window.location.search).get("invite") || "";
      const { data, error } = await supabase.functions.invoke(mode === "register" ? "register-pin" : "login-pin", { body: mode === "register" ? { display_name: displayName.trim(), pin, device_id, invite_code } : { pin, device_id } });
      if (error) throw error;
      if (data?.session?.access_token && data?.session?.refresh_token) {
        const { error: sessionError } = await supabase.auth.setSession(data.session);
        if (sessionError) throw sessionError;
      } else if (data?.error) throw new Error(data.error);
      else throw new Error("The authentication service is not ready yet.");
      setPin(""); setNotice("");
    } catch (err) {
      let message = mode === "register" ? "We couldn't create your account. Please try again." : "We couldn't log you in. Please check your PIN.";
      const response = (err && typeof err === "object" && "context" in err) ? (err as { context?: unknown }).context : undefined;
      if (response instanceof Response) {
        try {
          const payload = await response.clone().json() as { error?: string; message?: string };
          const serverMessage = payload.error || payload.message;
          if (response.status === 403) message = "Invalid invitation code. Check it and try again.";
          else if (response.status === 401) message = "Incorrect PIN. Please try again.";
          else if (response.status === 429) {
            message = (serverMessage && /seconds|wait/i.test(serverMessage)) ? serverMessage : "Too many attempts. Please wait a little before trying again.";
            const remaining = serverMessage?.match(/(\\d+)\\s*seconds?/i);
            setLockoutSeconds(remaining ? Math.min(30, Math.max(1, Number(remaining[1]))) : 30);
          }
          else if (response.status >= 500) message = "The authentication service is temporarily unavailable. Please try again later.";
          else if (serverMessage && serverMessage.length <= 180) message = serverMessage;
        } catch {
          const status = response.status;
          if (status === 401) message = "Incorrect PIN. Please try again.";
          else if (status === 403) message = "Invalid invitation code. Check it and try again.";
          else if (status === 429) { message = "Too many attempts. Please wait a little before trying again."; setLockoutSeconds(30); }
          else if (status >= 500) message = "The authentication service is temporarily unavailable. Please try again later.";
        }
      } else if (err instanceof Error && err.message && !/non-2xx|edge function/i.test(err.message)) {
        message = err.message;
      }
      if (mode === "login" && ((response instanceof Response && response.status === 429) || lockoutSeconds > 0)) { setNotice(""); setIsError(false); }
      else { setNotice(message); setIsError(true); }
    } finally { setBusy(false); }
  }


  async function loadMessages(chat: ChatItem, userId: string) {
    if (!supabase) return;
    const { data, error } = await supabase.from("messages").select("id,conversation_id,sender_id,ciphertext,nonce,created_at").eq("conversation_id", chat.id).is("deleted_at", null).order("created_at", { ascending: true }).limit(200);
    if (error) { setNotice("Couldn't load messages. Please refresh and try again."); setIsError(true); return; }
    const rows = (data || []) as MessageItem[];
    const decoded = await Promise.all(rows.map(async row => ({ ...row, text: await decryptMessage(supabase, userId, row.ciphertext, row.nonce) })));
    setMessages(decoded);
    const incoming = rows.filter(row => row.sender_id !== userId).map(row => row.id);
    if (incoming.length) {
      await supabase.from("message_receipts").update({ delivered_at: new Date().toISOString() }).eq("user_id", userId).in("message_id", incoming).is("delivered_at", null);
    }
  }

  async function sendMessage(e: React.FormEvent) {
    e.preventDefault();
    const text = draft.trim();
    if (!text || !selectedChat || !profile || !supabase || sending) return;
    setSending(true); setNotice(""); setIsError(false);
    try {
      const encrypted = await encryptMessage(supabase, profile.id, selectedChat.other.id, text);
      const { data, error } = await supabase.from("messages").insert({ conversation_id: selectedChat.id, sender_id: profile.id, ciphertext: encrypted.ciphertext, nonce: encrypted.nonce, key_version: 1 }).select("id,conversation_id,sender_id,ciphertext,nonce,created_at").single();
      if (error) throw error;
      setDraft("");
      setMessages(current => [...current, { ...(data as MessageItem), text }]);
      await loadChats(profile.id);
    } catch (error) {
      console.error("Message send failed", error);
      setNotice("Your message couldn’t be sent. Please try again.");
      setIsError(true);
    } finally { setSending(false); }
  }

  useEffect(() => {
    if (!selectedChat || !profile || !supabase) { setMessages([]); return; }
    void loadMessages(selectedChat, profile.id);
    const channel = supabase.channel("messages-" + selectedChat.id)
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "messages", filter: "conversation_id=eq." + selectedChat.id }, (payload) => {
        const row = payload.new as MessageItem;
        if (row.sender_id === profile.id) return;
        void decryptMessage(supabase, profile.id, row.ciphertext, row.nonce).then(async text => {
          setMessages(current => current.some(message => message.id === row.id) ? current : [...current, { ...row, text }]);
          await supabase.from("message_receipts").update({ delivered_at: new Date().toISOString() }).eq("message_id", row.id).eq("user_id", profile.id);
        });
      }).subscribe();
    return () => { void supabase.removeChannel(channel); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedChat?.id, profile?.id]);

  async function searchById() {
    if (!supabase || !/^\d{4}$/.test(search)) { setSearchNotice("Enter a valid 4-digit user ID."); return; }
    setSearching(true); setSearchNotice(""); setNotice(""); setIsError(false);
    const searchedId = search;
    const { data, error } = await supabase.from("profiles").select("id,public_id,display_name").eq("public_id", searchedId).maybeSingle();
    if (error || !data) {
      setSearch("");
      setSearchNotice("No matching member found.");
      setSearching(false);
      return;
    }
    if (data.id === profile?.id) { setSearchNotice("That is your own user ID."); setSearching(false); return; }
    const { data: conversationId, error: startError } = await supabase.rpc("start_one_to_one_conversation", { p_target_public_id: search });
    if (startError || !conversationId) {
      setNotice("Could not start the conversation. Please try again.");
      setIsError(true);
      setSearching(false);
      return;
    }
    const target = data as Profile;
    if (!mobileChatOpen) window.history.pushState({ chatAppView: "chat" }, "", window.location.href);
    setSelectedChat({ id: conversationId as string, other: target, last_message_at: new Date().toISOString() });
    setMobileChatOpen(true);
    setSearch("");
    setSearchNotice("");
    if (profile) await loadChats(profile.id);
    setSearching(false);
  }

  async function logout() {
    if (supabase) await supabase.auth.signOut();
    setSettingsOpen(false);
    setProfile(null);
    setSelectedChat(null);
    setChats([]);
    setDisplayName("");
    setPin("");
    setInviteCode("");
    setNotice("");
    setIsError(false);
    setMode("login");
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.delete("invite");
      window.history.replaceState({}, "", url.pathname + url.search + url.hash);
    }
  }

  if (!profile) return <main className="auth-shell">
    <section className="auth-art">
      <div className="brand"><span className="brand-mark"><MessageCircle size={19} strokeWidth={2.5}/></span> chat.</div>
      <div className="art-copy"><h1>Good conversations.<br/><span>Less noise.</span></h1><p>A quieter, more thoughtful space for your team&apos;s one-to-one conversations. Just your people, all in one place.</p>
        <div className="floating-chat"><div className="float-head"><div className="avatar">A</div><div><strong style={{fontSize:13}}>Aarav Mehta</strong><div style={{fontSize:11,color:"#8b94a7",marginTop:3}}>Online now</div></div><span style={{marginLeft:"auto",color:"#7c86a0"}}><MoreHorizontal size={19}/></span></div><div className="bubble left">Hey! I&apos;ve shared the updated plan with you.</div><div className="bubble right">Got it, thanks. I&apos;ll take a look ✨</div><div className="bubble left" style={{width:"61%"}}>Perfect. No rush!</div></div>
      </div>
      <div className="art-foot">Thoughtfully made for small teams · Private by design</div>
    </section>
    <section className="auth-panel"><div className="auth-card">
      <div className="brand" style={{marginBottom:35}}><span className="brand-mark"><MessageCircle size={19} strokeWidth={2.5}/></span> chat.</div>
      <h2>{mode === "login" ? "Welcome back" : "Create your account"}</h2><p className="subtext">{mode === "login" ? "Enter your private PIN to continue to your chats." : "Choose a display name and a unique 6-digit PIN."}</p>
      <div className="tabs"><button className={mode === "login" ? "active" : ""} onClick={() => {setMode("login");setNotice("");setIsError(false);setDisplayName("");setPin("");setInviteCode("");}}>Log in</button><button className={mode === "register" ? "active" : ""} onClick={() => {setMode("register");setNotice("");setIsError(false);setDisplayName("");setPin("");setInviteCode("");}}>Register</button></div>
      <form onSubmit={submitAuth}>
        {mode === "register" && <><div className="field"><label htmlFor="displayName">Your display name</label><input id="displayName" autoComplete="off" maxLength={40} placeholder="e.g. Alex Morgan" value={displayName} onChange={e => setDisplayName(e.target.value)} required/></div><div className="field"><label htmlFor="inviteCode">Team invitation code</label><input id="inviteCode" type="password" autoComplete="off" maxLength={128} placeholder="Enter invitation code" value={inviteCode} onChange={e => setInviteCode(e.target.value)} required={!new URLSearchParams(typeof window === "undefined" ? "" : window.location.search).get("invite")}/><span style={{fontSize:11,color:"#929bad"}}>Ask your app administrator for an invitation code. Keep it private.</span></div></> }
        <div className="field"><label htmlFor="pin">6-digit PIN</label><input id="pin" className="pin-input" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" value={pin} onChange={e => setPin(e.target.value.replace(/\D/g, "").slice(0,6))} required/><span style={{fontSize:11,color:"#929bad"}}>{mode === "register" ? "Your PIN must be unique. Never reuse a PIN from another account." : "After 3 incorrect attempts, sign-in is paused for 30 seconds."}</span></div>
        {mode === "login" && lockoutSeconds > 0 ? <div className="pin-lockout" role="status" aria-live="polite"><div className="pin-lockout-head"><span className="pin-lockout-copy"><LockKeyhole size={15}/><span><strong>Too many attempts</strong><small>You can try again in</small></span></span><strong className="pin-lockout-time">{String(Math.floor(lockoutSeconds / 60)).padStart(2,"0")}:{String(lockoutSeconds % 60).padStart(2,"0")}</strong></div><div className="pin-lockout-track"><div className="pin-lockout-progress" style={{width: (lockoutSeconds / 30 * 100) + "%"}}/></div></div> : notice && <div className={"notice " + (isError ? "error" : "")}>{notice}</div>}
        <button className="primary-btn" disabled={busy || (mode === "login" && lockoutSeconds > 0)}>{busy ? "Please wait…" : mode === "login" ? "Continue securely" : "Create account"} <span style={{float:"right"}}><ArrowRight size={16}/></span></button>
      </form>
      <p className="hint"><LockKeyhole size={13} style={{display:"inline",verticalAlign:"-2px",marginRight:5}}/> Private team access. Share your 4-digit user ID with teammates, never your PIN.</p>
    </div></section>
  </main>;

  return <main className={"app-shell theme-" + theme + " " + (mobileChatOpen ? "chat-open" : "")}>
    <aside className="sidebar"><div className="side-top"><div className="side-brand"><div className="brand"><span className="brand-mark"><MessageCircle size={18}/></span> chat.</div><button className="icon-btn theme-toggle" type="button" title={theme === "light" ? "Switch to dark mode" : "Switch to light mode"} aria-label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"} aria-pressed={theme === "dark"} onClick={() => setTheme(current => current === "light" ? "dark" : "light")}>{theme === "light" ? <Moon size={17}/> : <Sun size={17}/>}</button></div>
      <div className="search-wrap"><Search size={15}/><input value={search} onChange={e=>{setSearch(e.target.value.replace(/\D/g,"").slice(0,4));setSearchNotice("");}} inputMode="numeric" placeholder="Find by 4-digit user ID" onKeyDown={e=>{if(e.key==="Enter")void searchById();}}/></div>
      {search.length===4 && <button className="small-primary" style={{width:"100%",marginTop:9}} onClick={()=>void searchById()} disabled={searching}>{searching?"Searching…":"Find teammate"}</button>}
      {searchNotice && <div className="notice error" role="status" aria-live="polite" style={{marginTop:9,marginBottom:0}}>{searchNotice}</div>}
    </div><div className="section-label"><span>MESSAGES</span><span>{chats.length}</span></div>
      {chats.length ? <div className="chat-list">{chats.map(chat=><button className={"chat-row "+(selectedChat?.id===chat.id?"selected":"")} key={chat.id} onClick={()=>{if (!mobileChatOpen) window.history.pushState({ chatAppView: "chat" }, "", window.location.href);setSelectedChat(chat);setMobileChatOpen(true);}}><div className="avatar">{chat.other.display_name.slice(0,1).toUpperCase()}</div><div className="chat-info"><div className="chat-name-line"><span className="chat-name">{chat.other.display_name}</span><span className="chat-time">{new Date(chat.last_message_at).toLocaleDateString()}</span></div><div className="chat-preview">Open conversation</div></div></button>)}</div> : <div className="empty-list"><MessageCircle size={20} style={{margin:"0 auto 9px",opacity:.6}}/><div>No conversations yet</div><div>Search a teammate by their 4-digit ID to start chatting.</div></div>}
      <div className={"side-bottom" + (settingsOpen ? " settings-expanded" : "")}>{settingsOpen && <section className="settings-pop settings-pop-inline" role="dialog" aria-label="Account settings" onClick={e=>e.stopPropagation()}><h3>Account settings</h3><p>{profile.display_name}<br/><span className="settings-user-id-label">Your User ID:</span> <strong className="settings-user-id-value">{profile.public_id}</strong> <button type="button" className="copy-user-id-btn" onClick={()=>void copyUserId()} aria-label="Copy your User ID"><span>{userIdCopied ? "Copied!" : "Copy"}</span></button><br/>Keep your 6-digit PIN private.</p><button onClick={()=>void logout()}><LogOut size={14} style={{display:"inline",verticalAlign:"-3px",marginRight:6}}/>Logout</button></section>}<div className="profile-mini"><div className="avatar">{profile.display_name.slice(0,1).toUpperCase()}</div><div className="profile-copy"><strong>{profile.display_name}</strong><span>Your ID · {profile.public_id}</span></div><button className="icon-btn" title="Account settings" aria-label="Account settings" aria-expanded={settingsOpen} onClick={()=>{if (!settingsOpen) window.history.pushState({ chatAppView: "settings" }, "", window.location.href);setSettingsOpen(open=>!open);}}><Settings size={17}/></button></div></div>
    </aside>
    <section className="main-panel"><header className="main-top"><div style={{display:"flex",alignItems:"center",gap:11}}>{selectedChat && <button className="icon-btn back-btn" onClick={()=>{setSelectedChat(null);setMobileChatOpen(false);}}><ArrowLeft size={17}/></button>}<div><div className="top-title">{selectedChat ? selectedChat.other.display_name : "Your conversations"}</div><div className="top-sub">{selectedChat ? "User ID · "+selectedChat.other.public_id : "A little more focus, a little less noise."}</div></div></div><div className="top-actions"><div className="online-pill"><span className="online-dot"></span> Your private space</div><button className="icon-btn" title="Help and privacy"><ShieldCheck size={17}/></button></div></header>
      {selectedChat ? <div className="chat-view">
        <div className="messages-list">
          {messages.length ? messages.map(message => <div key={message.id} className={"message-line " + (message.sender_id === profile.id ? "mine" : "theirs")}><div className="message-bubble">{message.text || "Decrypting…"}</div><span className="message-meta">{new Date(message.created_at).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}{message.sender_id === profile.id ? " · Sent" : ""}</span></div>) : <div className="chat-placeholder"><div className="welcome-icon"><LockKeyhole size={28}/></div><h3 style={{fontFamily:"Manrope",color:"#263047"}}>Start your conversation</h3><p>Your conversations are kept private on this device. Keep this browser’s data safe so you can continue accessing your messages.</p></div>}
        </div>
        {notice && <div className={"notice " + (isError ? "error" : "")} style={{margin:"0 20px 10px"}}>{notice}</div>}
        <form className="composer" onSubmit={sendMessage}><div className="composer-inner active"><textarea aria-label="Message" value={draft} onChange={e=>setDraft(e.target.value)} placeholder="Write a secure message…" maxLength={4000} rows={1}/><button className="send-btn" type="submit" disabled={!draft.trim() || sending} aria-label="Send message">{sending ? "…" : <ArrowRight size={18}/>}</button></div><div className="composer-foot"><LockKeyhole size={12}/> Your privacy matters · Never share your PIN</div></form>
      </div> : <div className="content-center"><div className="welcome-card"><div className="welcome-icon"><Sparkles size={30}/></div><h2>Your space, your people.</h2><p>Start a private one-to-one conversation by searching for a teammate using their 4-digit user ID.</p><button className="small-primary" onClick={()=>document.querySelector<HTMLInputElement>(".search-wrap input")?.focus()}><Plus size={15} style={{display:"inline",verticalAlign:"-3px",marginRight:6}}/>Find a teammate</button><div style={{display:"flex",justifyContent:"center",gap:18,marginTop:28,color:"#9aa2b3",fontSize:11}}><span><ShieldCheck size={13} style={{display:"inline",verticalAlign:"-3px",marginRight:4}}/>Your privacy comes first</span><span><Users size={13} style={{display:"inline",verticalAlign:"-3px",marginRight:4}}/>Just you and one teammate</span></div></div></div>}
    </section>
    
  </main>;
}
