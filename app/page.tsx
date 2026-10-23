"use client";
import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, Check, ChevronDown, CircleHelp, LockKeyhole, LogOut, MessageCircle, MoreHorizontal, Plus, Search, Settings, ShieldCheck, Sparkles, Users, X } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

type Mode = "login" | "register";
type Profile = { id: string; public_id: string; display_name: string };
type ChatItem = { id: string; other: Profile; last_message_at: string };


function bytesToB64(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary);
}
function b64ToBytes(value: string) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}
async function ensureDeviceKey(client: any, userId: string) {
  const storageKey = "chat_private_key_v1";
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
  const { data: existing } = await client.from("devices").select("id").eq("user_id", userId).eq("identity_public_key", publicKeyB64).is("revoked_at", null).maybeSingle();
  if (!existing) {
    const { error } = await client.from("devices").insert({ user_id: userId, device_label: "This browser", identity_public_key: publicKeyB64 });
    if (error) throw error;
  }
  const privateKey = await window.crypto.subtle.importKey("pkcs8", privateKeyBytes, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  return { privateKey, publicKeyB64 };
}
async function encryptMessage(client: any, userId: string, recipientId: string, text: string) {
  const { publicKeyB64: ownPublicKey } = await ensureDeviceKey(client, userId);
  const { data: devices, error } = await client.from("devices").select("user_id,identity_public_key").in("user_id", [userId, recipientId]).is("revoked_at", null);
  if (error) throw error;
  const keys = new Map<string, string>();
  for (const device of (devices || [])) if (!keys.has(device.user_id)) keys.set(device.user_id, device.identity_public_key);
  keys.set(userId, ownPublicKey);
  if (!keys.has(recipientId)) throw new Error("Your teammate needs to open the app once to set up secure messaging.");
  const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const body = new Uint8Array(await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(text)));
  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
  const wrapped: Record<string, string> = {};
  for (const [memberId, keyB64] of keys) {
    const publicKey = await window.crypto.subtle.importKey("spki", b64ToBytes(keyB64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    wrapped[memberId] = bytesToB64(new Uint8Array(await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawAesKey)));
  }
  return { ciphertext: JSON.stringify({ v: 1, body: bytesToB64(body), keys: wrapped }), nonce: bytesToB64(iv) };
}
async function decryptMessage(client: any, userId: string, ciphertext: string, nonce: string) {
  try {
    const packet = JSON.parse(ciphertext) as { v: number; body: string; keys: Record<string, string> };
    if (packet.v !== 1 || !packet.keys?.[userId]) return "[This message isn't available on this device]";
    const { privateKey } = await ensureDeviceKey(client, userId);
    const rawKey = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, b64ToBytes(packet.keys[userId]));
    const aesKey = await window.crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
    const plain = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(nonce) }, aesKey, b64ToBytes(packet.body));
    return new TextDecoder().decode(plain);
  } catch {
    return "[Unable to decrypt this message on this device]";
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
  const [notice, setNotice] = useState("");
  const [isError, setIsError] = useState(false);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [chats, setChats] = useState<ChatItem[]>([]);
  const [search, setSearch] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selectedChat, setSelectedChat] = useState<ChatItem | null>(null);
  const [mobileChatOpen, setMobileChatOpen] = useState(false);
  const [searching, setSearching] = useState(false);\n  const [messages, setMessages] = useState<MessageItem[]>([]);\n  const [draft, setDraft] = useState("");\n  const [sending, setSending] = useState(false);

  const supabase = useMemo(() => createClient(), []);

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
    const { data: memberships } = await supabase.from("conversation_members").select("conversation_id,last_read_at").order("joined_at", { ascending: false });
    if (!memberships?.length) { setChats([]); return; }
    const result: ChatItem[] = [];
    for (const membership of memberships) {
      const { data: members } = await supabase.from("conversation_members").select("user_id,profiles(id,public_id,display_name)").eq("conversation_id", membership.conversation_id);
      const other = (members || []).map((m: any) => m.profiles).find((p: Profile | null) => p && p.id !== userId);
      const { data: conversation } = await supabase.from("conversations").select("id,last_message_at").eq("id", membership.conversation_id).maybeSingle();
      if (other && conversation) result.push({ id: conversation.id, other, last_message_at: conversation.last_message_at });
    }
    setChats(result);
  }

  async function submitAuth(e: React.FormEvent) {
    e.preventDefault(); setNotice(""); setIsError(false);
    if (mode === "register" && displayName.trim().length < 2) { setNotice("Please enter a name with at least 2 characters."); setIsError(true); return; }
    if (mode === "register" && !inviteCode.trim() && !new URLSearchParams(window.location.search).get("invite")) { setNotice("Enter your team invitation code to register."); setIsError(true); return; }
    if (!/^\d{6}$/.test(pin)) { setNotice("Enter your 6-digit PIN."); setIsError(true); return; }
    if (!supabase) { setNotice("Supabase is not configured yet. Add the project URL and publishable key to the deployment environment."); setIsError(true); return; }
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
          else if (response.status === 429) message = (serverMessage && /seconds|wait/i.test(serverMessage)) ? serverMessage : "Too many attempts. Please wait a little before trying again.";
          else if (response.status >= 500) message = "The authentication service is temporarily unavailable. Please try again later.";
          else if (serverMessage && serverMessage.length <= 180) message = serverMessage;
        } catch {
          const status = response.status;
          if (status === 401) message = "Incorrect PIN. Please try again.";
          else if (status === 403) message = "Invalid invitation code. Check it and try again.";
          else if (status === 429) message = "Too many attempts. Please wait a little before trying again.";
          else if (status >= 500) message = "The authentication service is temporarily unavailable. Please try again later.";
        }
      } else if (err instanceof Error && err.message && !/non-2xx|edge function/i.test(err.message)) {
        message = err.message;
      }
      setNotice(message); setIsError(true);
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
      setNotice(error instanceof Error ? error.message : "Message couldn't be sent. Please try again.");
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
    if (!supabase || !/^\d{4}$/.test(search)) { setNotice("Enter a valid 4-digit user ID."); setIsError(true); return; }
    setSearching(true); setNotice(""); setIsError(false);
    const { data, error } = await supabase.from("profiles").select("id,public_id,display_name").eq("public_id", search).maybeSingle();
    if (error || !data) { setNotice("No matching member found."); setIsError(true); setSearching(false); return; }
    if (data.id === profile?.id) { setNotice("That is your own user ID."); setIsError(true); setSearching(false); return; }
    const { data: conversationId, error: startError } = await supabase.rpc("start_one_to_one_conversation", { p_target_public_id: search });
    if (startError || !conversationId) {
      setNotice("Could not start the conversation. Please try again.");
      setIsError(true);
      setSearching(false);
      return;
    }
    const target = data as Profile;
    setSelectedChat({ id: conversationId as string, other: target, last_message_at: new Date().toISOString() });
    setMobileChatOpen(true);
    setSearch("");
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
      <div className="art-copy"><h1>Good conversations.<br/><span>Less noise.</span></h1><p>A quieter, more thoughtful space for your team's one-to-one conversations. Just your people, all in one place.</p>
        <div className="floating-chat"><div className="float-head"><div className="avatar">A</div><div><strong style={{fontSize:13}}>Aarav Mehta</strong><div style={{fontSize:11,color:"#8b94a7",marginTop:3}}>Online now</div></div><span style={{marginLeft:"auto",color:"#7c86a0"}}><MoreHorizontal size={19}/></span></div><div className="bubble left">Hey! I've shared the updated plan with you.</div><div className="bubble right">Got it, thanks. I'll take a look ✨</div><div className="bubble left" style={{width:"61%"}}>Perfect. No rush!</div></div>
      </div>
      <div className="art-foot">Thoughtfully made for small teams · Private by design</div>
    </section>
    <section className="auth-panel"><div className="auth-card">
      <div className="brand" style={{marginBottom:35}}><span className="brand-mark"><MessageCircle size={19} strokeWidth={2.5}/></span> chat.</div>
      <h2>{mode === "login" ? "Welcome back" : "Create your account"}</h2><p className="subtext">{mode === "login" ? "Enter your private PIN to continue to your chats." : "Choose a display name and a unique 6-digit PIN."}</p>
      <div className="tabs"><button className={mode === "login" ? "active" : ""} onClick={() => {setMode("login");setNotice("");setIsError(false);setDisplayName("");setPin("");setInviteCode("");}}>Log in</button><button className={mode === "register" ? "active" : ""} onClick={() => {setMode("register");setNotice("");setIsError(false);setDisplayName("");setPin("");setInviteCode("");}}>Register</button></div>
      <form onSubmit={submitAuth}>
        {mode === "register" && <><div className="field"><label htmlFor="displayName">Your display name</label><input id="displayName" autoComplete="off" maxLength={40} placeholder="e.g. Alex Morgan" value={displayName} onChange={e => setDisplayName(e.target.value)} required/></div><div className="field"><label htmlFor="inviteCode">Team invitation code</label><input id="inviteCode" type="password" autoComplete="off" maxLength={128} placeholder="Enter invitation code" value={inviteCode} onChange={e => setInviteCode(e.target.value)} required={!new URLSearchParams(typeof window === "undefined" ? "" : window.location.search).get("invite")}/><span style={{fontSize:11,color:"#929bad"}}>Ask your app administrator for an invitation code. Keep it private.</span></div></> }
        <div className="field"><label htmlFor="pin">6-digit PIN</label><input id="pin" className="pin-input" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="••••••" value={pin} onChange={e => setPin(e.target.value.replace(/\D/g, "").slice(0,6))} required/><span style={{fontSize:11,color:"#929bad"}}>{mode === "register" ? "Your PIN must be unique. Never reuse a PIN from another account." : "After 3 incorrect attempts, sign-in is paused for 30 seconds."}</span></div>
        {notice && <div className={"notice " + (isError ? "error" : "")}>{notice}</div>}
        <button className="primary-btn" disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Continue securely" : "Create account"} <span style={{float:"right"}}><ArrowRight size={16}/></span></button>
      </form>
      <p className="hint"><LockKeyhole size={13} style={{display:"inline",verticalAlign:"-2px",marginRight:5}}/> Private team access. Share your 4-digit user ID with teammates, never your PIN.</p>
    </div></section>
  </main>;

  return <main className={"app-shell " + (mobileChatOpen ? "chat-open" : "")}>
    <aside className="sidebar"><div className="side-top"><div className="side-brand"><div className="brand"><span className="brand-mark"><MessageCircle size={18}/></span> chat.</div><button className="icon-btn" title="Settings" onClick={() => setSettingsOpen(!settingsOpen)}><Settings size={17}/></button></div>
      <div className="search-wrap"><Search size={15}/><input value={search} onChange={e=>setSearch(e.target.value.replace(/\D/g,"").slice(0,4))} inputMode="numeric" placeholder="Find by 4-digit user ID" onKeyDown={e=>{if(e.key==="Enter")void searchById();}}/></div>
      {search.length===4 && <button className="small-primary" style={{width:"100%",marginTop:9}} onClick={()=>void searchById()} disabled={searching}>{searching?"Searching…":"Find teammate"}</button>}
      {notice && <div className={"notice " + (isError ? "error" : "")} style={{marginTop:9,marginBottom:0}}>{notice}</div>}
    </div><div className="section-label"><span>MESSAGES</span><span>{chats.length}</span></div>
      {chats.length ? <div className="chat-list">{chats.map(chat=><button className={"chat-row "+(selectedChat?.id===chat.id?"selected":"")} key={chat.id} onClick={()=>{setSelectedChat(chat);setMobileChatOpen(true);}}><div className="avatar">{chat.other.display_name.slice(0,1).toUpperCase()}</div><div className="chat-info"><div className="chat-name-line"><span className="chat-name">{chat.other.display_name}</span><span className="chat-time">{new Date(chat.last_message_at).toLocaleDateString()}</span></div><div className="chat-preview">Open conversation</div></div></button>)}</div> : <div className="empty-list"><MessageCircle size={20} style={{margin:"0 auto 9px",opacity:.6}}/><div>No conversations yet</div><div>Search a teammate by their 4-digit ID to start chatting.</div></div>}
      <div className="side-bottom"><div className="profile-mini"><div className="avatar">{profile.display_name.slice(0,1).toUpperCase()}</div><div className="profile-copy"><strong>{profile.display_name}</strong><span>Your ID · {profile.public_id}</span></div><button className="icon-btn" title="Account settings" onClick={()=>setSettingsOpen(!settingsOpen)}><ChevronDown size={15}/></button></div></div>
    </aside>
    <section className="main-panel"><header className="main-top"><div style={{display:"flex",alignItems:"center",gap:11}}>{selectedChat && <button className="icon-btn back-btn" onClick={()=>{setSelectedChat(null);setMobileChatOpen(false);}}><ArrowLeft size={17}/></button>}<div><div className="top-title">{selectedChat ? selectedChat.other.display_name : "Your conversations"}</div><div className="top-sub">{selectedChat ? "User ID · "+selectedChat.other.public_id : "A little more focus, a little less noise."}</div></div></div><div className="top-actions"><div className="online-pill"><span className="online-dot"></span> Private workspace</div><button className="icon-btn" title="Help and privacy"><ShieldCheck size={17}/></button></div></header>
      {selectedChat ? <div className="chat-view">
        <div className="messages-list">
          {messages.length ? messages.map(message => <div key={message.id} className={"message-line " + (message.sender_id === profile.id ? "mine" : "theirs")}><div className="message-bubble">{message.text || "Decrypting…"}</div><span className="message-meta">{new Date(message.created_at).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}{message.sender_id === profile.id ? " · Sent" : ""}</span></div>) : <div className="chat-placeholder"><div className="welcome-icon"><LockKeyhole size={28}/></div><h3 style={{fontFamily:"Manrope",color:"#263047"}}>Start your conversation</h3><p>Messages are encrypted on this device before they are saved. Keep your browser data safe so this device can decrypt its messages.</p></div>}
        </div>
        {notice && <div className={"notice " + (isError ? "error" : "")} style={{margin:"0 20px 10px"}}>{notice}</div>}
        <form className="composer" onSubmit={sendMessage}><div className="composer-inner active"><textarea aria-label="Message" value={draft} onChange={e=>setDraft(e.target.value)} placeholder="Write a secure message…" maxLength={4000} rows={1}/><button className="send-btn" type="submit" disabled={!draft.trim() || sending} aria-label="Send message">{sending ? "…" : <ArrowRight size={18}/>}</button></div><div className="composer-foot"><LockKeyhole size={12}/> Encrypted on this device · Never share your PIN</div></form>
      </div> : <div className="content-center"><div className="welcome-card"><div className="welcome-icon"><Sparkles size={30}/></div><h2>Your space, your people.</h2><p>Start a private one-to-one conversation by searching for a teammate using their 4-digit user ID.</p><button className="small-primary" onClick={()=>document.querySelector<HTMLInputElement>(".search-wrap input")?.focus()}><Plus size={15} style={{display:"inline",verticalAlign:"-3px",marginRight:6}}/>Find a teammate</button><div style={{display:"flex",justifyContent:"center",gap:18,marginTop:28,color:"#9aa2b3",fontSize:11}}><span><ShieldCheck size={13} style={{display:"inline",verticalAlign:"-3px",marginRight:4}}/>Privacy-first</span><span><Users size={13} style={{display:"inline",verticalAlign:"-3px",marginRight:4}}/>1:1 only</span></div></div></div>}
    </section>
    {settingsOpen && <div className="settings-pop"><h3>Account settings</h3><p>{profile.display_name}<br/>Shareable user ID: <strong>{profile.public_id}</strong><br/>Keep your 6-digit PIN private.</p><button onClick={()=>void logout()}><LogOut size={14} style={{display:"inline",verticalAlign:"-3px",marginRight:6}}/>Sign out</button></div>}
  </main>;
}
