"use client";
import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, Check, ChevronDown, CircleHelp, LockKeyhole, LogOut, MessageCircle, MoreHorizontal, Plus, Search, Settings, ShieldCheck, Sparkles, Users, X } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

type Mode = "login" | "register";
type Profile = { id: string; public_id: string; display_name: string };
type ChatItem = { id: string; other: Profile; last_message_at: string };

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
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [isError, setIsError] = useState(false);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [chats, setChats] = useState<ChatItem[]>([]);
  const [search, setSearch] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selectedChat, setSelectedChat] = useState<ChatItem | null>(null);
  const [mobileChatOpen, setMobileChatOpen] = useState(false);
  const [searching, setSearching] = useState(false);

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
    if (data) { setProfile(data as Profile); await loadChats(userId); }
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
    if (!/^\d{6}$/.test(pin)) { setNotice("Enter your 6-digit PIN."); setIsError(true); return; }
    if (!supabase) { setNotice("Supabase is not configured yet. Add the project URL and publishable key to the deployment environment."); setIsError(true); return; }
    setBusy(true);
    try {
      const device_id = getDeviceId();
      const invite_code = new URLSearchParams(window.location.search).get("invite") ?? "";
      const { data, error } = await supabase.functions.invoke(mode === "register" ? "register-pin" : "login-pin", { body: mode === "register" ? { display_name: displayName.trim(), pin, device_id, invite_code } : { pin, device_id } });
      if (error) throw error;
      if (data?.session?.access_token && data?.session?.refresh_token) {
        const { error: sessionError } = await supabase.auth.setSession(data.session);
        if (sessionError) throw sessionError;
      } else if (data?.error) throw new Error(data.error);
      else throw new Error("The authentication service is not ready yet.");
      setPin(""); setNotice("");
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "Unable to sign in right now."); setIsError(true);
    } finally { setBusy(false); }
  }

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
    setSettingsOpen(false); setProfile(null); setSelectedChat(null); setChats([]);
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
      <div className="tabs"><button className={mode === "login" ? "active" : ""} onClick={() => {setMode("login");setNotice("");}}>Log in</button><button className={mode === "register" ? "active" : ""} onClick={() => {setMode("register");setNotice("");}}>Register</button></div>
      <form onSubmit={submitAuth}>
        {mode === "register" && <div className="field"><label htmlFor="displayName">Your display name</label><input id="displayName" autoComplete="nickname" maxLength={40} placeholder="e.g. Alex Morgan" value={displayName} onChange={e => setDisplayName(e.target.value)} required/></div>}
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
      {selectedChat ? <div className="chat-view"><div className="chat-placeholder"><div className="welcome-icon"><LockKeyhole size={28}/></div><h3 style={{fontFamily:"Manrope",color:"#263047"}}>Secure messaging is being prepared</h3><p>Messages will be enabled after end-to-end encryption and delivery receipts are implemented and tested. Your message content will not be sent as plaintext.</p></div><div className="composer"><div className="composer-inner"><span>Secure message composer · not enabled yet</span><LockKeyhole size={15}/></div></div></div> : <div className="content-center"><div className="welcome-card"><div className="welcome-icon"><Sparkles size={30}/></div><h2>Your space, your people.</h2><p>Start a private one-to-one conversation by searching for a teammate using their 4-digit user ID.</p><button className="small-primary" onClick={()=>document.querySelector<HTMLInputElement>(".search-wrap input")?.focus()}><Plus size={15} style={{display:"inline",verticalAlign:"-3px",marginRight:6}}/>Find a teammate</button><div style={{display:"flex",justifyContent:"center",gap:18,marginTop:28,color:"#9aa2b3",fontSize:11}}><span><ShieldCheck size={13} style={{display:"inline",verticalAlign:"-3px",marginRight:4}}/>Privacy-first</span><span><Users size={13} style={{display:"inline",verticalAlign:"-3px",marginRight:4}}/>1:1 only</span></div></div></div>}
    </section>
    {settingsOpen && <div className="settings-pop"><h3>Account settings</h3><p>{profile.display_name}<br/>Shareable user ID: <strong>{profile.public_id}</strong><br/>Keep your 6-digit PIN private.</p><button onClick={()=>void logout()}><LogOut size={14} style={{display:"inline",verticalAlign:"-3px",marginRight:6}}/>Sign out</button></div>}
  </main>;
}
