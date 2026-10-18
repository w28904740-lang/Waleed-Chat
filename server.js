const express = require("express");
const http = require("http");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Server } = require("socket.io");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const DB_FILE = path.join(__dirname, "data.json");

function loadDB() {
  try {
    const d = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    return { users: Array.isArray(d.users) ? d.users : [], messages: Array.isArray(d.messages) ? d.messages : [] };
  } catch {
    return { users: [], messages: [] };
  }
}
let db = loadDB();
function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), "utf8");
}
function cleanUser(u) {
  return { id: u.id, name: u.name, phone: u.phone };
}
function pairKey(a, b) {
  return [a, b].sort().join("__");
}
function isValidPhone(phone) {
  return /^[0-9+\-\s()]{7,20}$/.test(phone);
}
app.use(express.json({ limit: "1mb" }));
const sessionMiddleware = session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7 * 24 * 60 * 60 * 1000 }
});
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));
io.engine.use(sessionMiddleware);

function requireAuth(req, res, next) {
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: "سجّل الدخول الأول." });
  req.user = user;
  next();
}

app.get("/api/me", (req, res) => {
  const user = db.users.find(u => u.id === req.session.userId);
  res.json({ user: user ? cleanUser(user) : null });
});

app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim().slice(0, 40);
    const phone = String(req.body.phone || "").replace(/\s+/g, "");
    const password = String(req.body.password || "");
    if (name.length < 2) return res.status(400).json({ error: "اكتب اسمًا من حرفين على الأقل." });
    if (!isValidPhone(phone)) return res.status(400).json({ error: "اكتب رقم موبايل صحيحًا." });
    if (password.length < 8) return res.status(400).json({ error: "كلمة السر لازم تكون 8 أحرف على الأقل." });
    if (db.users.some(u => u.phone === phone)) return res.status(409).json({ error: "الرقم ده مسجل بالفعل. جرّب تسجيل الدخول." });
    const user = { id: crypto.randomUUID(), name, phone, passwordHash: await bcrypt.hash(password, 12), createdAt: new Date().toISOString() };
    db.users.push(user);
    saveDB();
    req.session.userId = user.id;
    req.session.save(() => res.json({ user: cleanUser(user) }));
  } catch {
    res.status(500).json({ error: "حصل خطأ أثناء إنشاء الحساب." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const phone = String(req.body.phone || "").replace(/\s+/g, "");
    const password = String(req.body.password || "");
    const user = db.users.find(u => u.phone === phone);
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: "رقم الموبايل أو كلمة السر غير صحيحة." });
    }
    req.session.userId = user.id;
    req.session.save(() => res.json({ user: cleanUser(user) }));
  } catch {
    res.status(500).json({ error: "حصل خطأ أثناء تسجيل الدخول." });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/search", requireAuth, (req, res) => {
  const q = String(req.query.phone || "").replace(/\s+/g, "");
  if (q.length < 4) return res.json({ users: [] });
  const users = db.users
    .filter(u => u.id !== req.user.id && u.phone.includes(q))
    .slice(0, 20)
    .map(cleanUser);
  res.json({ users });
});

app.get("/api/chats", requireAuth, (req, res) => {
  const others = new Map();
  for (const m of db.messages) {
    if (m.fromId === req.user.id) {
      const u = db.users.find(x => x.id === m.toId);
      if (u) others.set(u.id, u);
    } else if (m.toId === req.user.id) {
      const u = db.users.find(x => x.id === m.fromId);
      if (u) others.set(u.id, u);
    }
  }
  res.json({ users: [...others.values()].map(cleanUser) });
});

app.get("/api/messages/:otherId", requireAuth, (req, res) => {
  const other = db.users.find(u => u.id === req.params.otherId);
  if (!other || other.id === req.user.id) return res.status(404).json({ error: "الحساب غير موجود." });
  const messages = db.messages
    .filter(m => (m.fromId === req.user.id && m.toId === other.id) || (m.fromId === other.id && m.toId === req.user.id))
    .slice(-300);
  res.json({ messages, other: cleanUser(other) });
});

app.post("/api/messages", requireAuth, (req, res) => {
  const toId = String(req.body.toId || "");
  const text = String(req.body.text || "").trim();
  const recipient = db.users.find(u => u.id === toId);
  if (!recipient || recipient.id === req.user.id) return res.status(400).json({ error: "اختار حسابًا صحيحًا." });
  if (!text || text.length > 2000) return res.status(400).json({ error: "الرسالة لازم تكون من 1 إلى 2000 حرف." });
  const message = {
    id: crypto.randomUUID(),
    fromId: req.user.id,
    toId: recipient.id,
    text,
    createdAt: new Date().toISOString()
  };
  db.messages.push(message);
  saveDB();
  io.to(pairKey(req.user.id, recipient.id)).emit("new-message", message);
  res.json({ message });
});

const onlineUsers = new Map();
io.use((socket, next) => {
  const userId = socket.request.session && socket.request.session.userId;
  const user = db.users.find(u => u.id === userId);
  if (!user) return next(new Error("غير مسجل"));
  socket.user = user;
  next();
});
io.on("connection", socket => {
  const userId = socket.user.id;
  onlineUsers.set(userId, (onlineUsers.get(userId) || 0) + 1);
  io.emit("presence", { userId, online: true });
  socket.on("join-chat", otherId => {
    const other = db.users.find(u => u.id === String(otherId));
    if (!other || other.id === userId) return;
    socket.join(pairKey(userId, other.id));
  });
  socket.on("disconnect", () => {
    const count = (onlineUsers.get(userId) || 1) - 1;
    if (count <= 0) {
      onlineUsers.delete(userId);
      io.emit("presence", { userId, online: false });
    } else {
      onlineUsers.set(userId, count);
    }
  });
});
app.get("/api/online", requireAuth, (req, res) => {
  res.json({ userIds: [...onlineUsers.keys()] });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Waleed Chat is running on port ${PORT}`);
});
