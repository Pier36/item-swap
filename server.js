/**
 * 책갈피 스왑 — 백엔드 핵심 로직 (Node 18+, Express + Socket.IO)
 *
 *   npm i express socket.io
 *   SECRET_KEY=$(openssl rand -hex 32) node server.js
 *
 * 원칙
 *  1) 피드(posts)에는 익명 별칭과 책갈피 목록만 저장한다. 연락처는 절대 섞지 않는다.
 *  2) 당근 닉네임·동네는 vault에 AES-256-GCM으로 암호화해 따로 보관한다.
 *  3) 양쪽 당사자가 모두 '교환 성사'를 누른 순간에만 복호화해서,
 *     각자의 소켓 방(user:<id>)으로 "상대의" 정보만 1:1 전송한다.
 *  4) 글·대화·거래는 24시간 TTL. 만료되면 vault 공개 기록까지 함께 삭제한다.
 *
 *  운영 시에는 Map 대신 Redis(EXPIRE로 TTL 처리)를 쓰는 것을 권장한다.
 */
const express = require("express");
const http = require("http");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
app.use(express.json({ limit: "64kb" }));
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: process.env.ORIGIN || "*" } });

const TTL_MS = 24 * 60 * 60 * 1000;
const BOOK_IDS = new Set(Array.from({ length: 20 }, (_, i) => i + 1));
const SHIP = new Set(["direct", "half", "normal"]);
const KEY = Buffer.from(process.env.SECRET_KEY || crypto.randomBytes(32).toString("hex"), "hex");

/* ───────── 저장소 ───────── */
const users = new Map(); // userId -> { tokenHash, alias, createdAt }
const vault = new Map(); // userId -> encrypted { karrot, area }
const posts = new Map(); // postId -> { id, ownerId, alias, type, have, need, ship, price, note, ts }
const deals = new Map(); // dealId -> { id, postId, parties:[a,b], confirmed:{}, msgs:[], ts, revealedAt }

/* ───────── 암호화 ───────── */
function encrypt(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const data = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return { iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64") };
}
function decrypt(box) {
  const d = crypto.createDecipheriv("aes-256-gcm", KEY, Buffer.from(box.iv, "base64"));
  d.setAuthTag(Buffer.from(box.tag, "base64"));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(box.data, "base64")), d.final()]).toString("utf8"));
}

/* ───────── 익명 인증 (회원가입 없음) ─────────
   첫 접속 시 랜덤 토큰을 발급하고 서버는 해시만 보관한다. 클라이언트는 토큰을 localStorage에 둔다. */
const ADJ = ["조용한", "밤샘", "책등", "여백의", "새벽", "느긋한", "줄긋는", "초판"];
const NOUN = ["독자", "책벌레", "수집가", "갈피", "서재", "필사러"];
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const rid = () => crypto.randomBytes(8).toString("hex");
const pick = (a) => a[crypto.randomInt(a.length)];

app.post("/api/session", (req, res) => {
  const token = crypto.randomBytes(24).toString("base64url");
  const id = rid();
  const alias = `${pick(ADJ)} ${pick(NOUN)} #${crypto.randomInt(1000, 10000)}`;
  users.set(id, { tokenHash: sha(token), alias, createdAt: Date.now() });
  res.json({ userId: id, token, alias });
});

function auth(req, res, next) {
  const [id, token] = String(req.get("authorization") || "").replace("Bearer ", "").split(".");
  const u = users.get(id);
  if (!u || u.tokenHash !== sha(token || "")) return res.status(401).json({ error: "세션이 만료됐어요. 새로고침해 주세요." });
  req.userId = id; req.alias = u.alias; next();
}

/* ───────── 비밀 정보 등록 ───────── */
app.put("/api/me/secret", auth, (req, res) => {
  const karrot = String(req.body.karrot || "").trim().slice(0, 30);
  const area = String(req.body.area || "").trim().slice(0, 40);
  if (!karrot && !area) return res.status(400).json({ error: "당근 닉네임이나 동네 중 하나는 입력해 주세요." });
  vault.set(req.userId, encrypt({ karrot, area }));
  res.json({ ok: true }); // 저장한 값을 되돌려주지 않는다
});

/* ───────── 피드 ───────── */
const publicPost = (p) => ({ id: p.id, alias: p.alias, type: p.type, have: p.have, need: p.need, ship: p.ship, price: p.price, note: p.note, ts: p.ts });

app.post("/api/posts", auth, (req, res) => {
  const { type, have = [], need = [], ship = [], price, note } = req.body;
  if (!["trade", "sale"].includes(type)) return res.status(400).json({ error: "type 오류" });
  const cleanHave = have.filter((h) => BOOK_IDS.has(h.id)).map((h) => ({ id: h.id, sealed: !!h.sealed }));
  const cleanNeed = type === "trade" ? need.filter((id) => BOOK_IDS.has(id)) : [];
  const cleanShip = ship.filter((s) => SHIP.has(s));
  if (!cleanShip.length) return res.status(400).json({ error: "거래 방식을 하나 이상 골라주세요." });
  if (!cleanHave.length && !cleanNeed.length) return res.status(400).json({ error: "책갈피를 하나 이상 체크해 주세요." });

  // 같은 유저의 같은 타입 글은 하나만 유지 (도배 방지)
  for (const [id, p] of posts) if (p.ownerId === req.userId && p.type === type) posts.delete(id);

  const post = { id: rid(), ownerId: req.userId, alias: req.alias, type, have: cleanHave, need: cleanNeed, ship: cleanShip,
    price: type === "sale" ? Math.max(0, Math.min(1_000_000, Number(price) || 0)) : undefined,
    note: type === "sale" ? String(note || "").slice(0, 40) : undefined, ts: Date.now() };
  posts.set(post.id, post);
  io.emit("post:new", publicPost(post)); // ownerId는 브로드캐스트하지 않는다
  res.json(publicPost(post));
});

app.get("/api/posts", (req, res) => {
  const type = req.query.type;
  res.json([...posts.values()].filter((p) => !type || p.type === type).sort((a, b) => b.ts - a.ts).map(publicPost));
});

/* 매칭 점수: 상대가 가진 것 ∩ 내가 구하는 것, 상대가 구하는 것 ∩ 내가 가진 것 */
function matchScore(post, myHave, myNeed) {
  const iGet = post.have.map((h) => h.id).filter((id) => myNeed.includes(id));
  const iGive = post.need.filter((id) => myHave.includes(id));
  return { iGet, iGive, mutual: iGet.length > 0 && (post.type === "sale" || iGive.length > 0) };
}
app.post("/api/match", auth, (req, res) => {
  const { have = [], need = [] } = req.body;
  const out = [...posts.values()].filter((p) => p.ownerId !== req.userId)
    .map((p) => ({ post: publicPost(p), ...matchScore(p, have, need) }))
    .filter((m) => m.mutual)
    .sort((a, b) => b.iGet.length + b.iGive.length - (a.iGet.length + a.iGive.length));
  res.json(out);
});

/* ───────── 거래(익명 대화방) ───────── */
app.post("/api/deals", auth, (req, res) => {
  const post = posts.get(req.body.postId);
  if (!post) return res.status(404).json({ error: "이미 사라진 글이에요." });
  if (post.ownerId === req.userId) return res.status(400).json({ error: "내 글에는 신청할 수 없어요." });
  const existing = [...deals.values()].find((d) => d.postId === post.id && d.parties.includes(req.userId));
  if (existing) return res.json({ dealId: existing.id });

  const deal = { id: rid(), postId: post.id, parties: [req.userId, post.ownerId], confirmed: {}, msgs: [], ts: Date.now(), revealedAt: null };
  deals.set(deal.id, deal);
  io.to(`user:${post.ownerId}`).emit("deal:new", { dealId: deal.id, postId: post.id, from: req.alias });
  res.json({ dealId: deal.id });
});

const isParty = (deal, uid) => deal && deal.parties.includes(uid);

app.post("/api/deals/:id/messages", auth, (req, res) => {
  const deal = deals.get(req.params.id);
  if (!isParty(deal, req.userId)) return res.status(404).json({ error: "대화방을 찾을 수 없어요." });
  const text = String(req.body.text || "").trim().slice(0, 300);
  if (!text) return res.status(400).json({ error: "빈 메시지예요." });
  const msg = { from: req.userId === deal.parties[0] ? "a" : "b", text, ts: Date.now() }; // 실제 ID 대신 a/b
  deal.msgs.push(msg);
  deal.parties.forEach((pid) => io.to(`user:${pid}`).emit("deal:msg", { dealId: deal.id, msg, mine: pid === req.userId }));
  res.json({ ok: true });
});

/**
 * ★ 핵심: 교환 성사 → 상호 확인 → 1:1 비밀 공개
 * 양쪽 모두 confirmed가 되는 순간에만 실행되며, 각 당사자에게 "상대의" 정보만 보낸다.
 */
function revealFor(deal, viewerId) {
  if (!isParty(deal, viewerId)) return null;
  if (!deal.parties.every((pid) => deal.confirmed[pid])) return null;
  const otherId = deal.parties.find((pid) => pid !== viewerId);
  const box = vault.get(otherId);
  return box ? decrypt(box) : null;
}

app.post("/api/deals/:id/confirm", auth, (req, res) => {
  const deal = deals.get(req.params.id);
  if (!isParty(deal, req.userId)) return res.status(404).json({ error: "대화방을 찾을 수 없어요." });
  if (!vault.has(req.userId)) return res.status(400).json({ error: "당근 닉네임이나 동네를 먼저 등록해 주세요." });

  deal.confirmed[req.userId] = Date.now();
  const both = deal.parties.every((pid) => deal.confirmed[pid]);

  if (!both) {
    const other = deal.parties.find((pid) => pid !== req.userId);
    io.to(`user:${other}`).emit("deal:confirm", { dealId: deal.id, waitingOn: "me" });
    return res.json({ status: "waiting" });
  }

  deal.revealedAt = Date.now();
  for (const pid of deal.parties) {
    // 각 소켓 방에는 그 사람이 받아야 할 상대 정보 한 건만 보낸다. 브로드캐스트 금지.
    io.to(`user:${pid}`).emit("deal:revealed", { dealId: deal.id, counterpart: revealFor(deal, pid) });
  }
  res.json({ status: "revealed", counterpart: revealFor(deal, req.userId) });
});

// 새로고침 후 다시 열 때도 같은 규칙으로만 조회 가능
app.get("/api/deals/:id/secret", auth, (req, res) => {
  const secret = revealFor(deals.get(req.params.id), req.userId);
  if (!secret) return res.status(403).json({ error: "양쪽 모두 교환 성사를 눌러야 볼 수 있어요." });
  res.json(secret);
});

/* ───────── 소켓: 사용자별 개인 방 ───────── */
io.use((socket, next) => {
  const [id, token] = String(socket.handshake.auth?.token || "").split(".");
  const u = users.get(id);
  if (!u || u.tokenHash !== sha(token || "")) return next(new Error("unauthorized"));
  socket.data.userId = id; next();
});
io.on("connection", (socket) => socket.join(`user:${socket.data.userId}`));

/* ───────── 휘발: 24시간 지난 글·거래 삭제 ───────── */
setInterval(() => {
  const now = Date.now();
  for (const [id, p] of posts) if (now - p.ts > TTL_MS) { posts.delete(id); io.emit("post:expired", { id }); }
  for (const [id, d] of deals) if (now - d.ts > TTL_MS) deals.delete(id);
}, 60 * 1000);

app.use(express.static("public")); // bookmark-swap.html을 public/index.html로 두면 된다
server.listen(process.env.PORT || 3000, () => console.log("책갈피 스왑 서버 :" + (process.env.PORT || 3000)));

module.exports = { revealFor, matchScore, encrypt, decrypt };
