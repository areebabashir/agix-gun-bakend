import "dotenv/config";
import { randomUUID } from "crypto";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json({ limit: "200kb" }));
const allowed = (process.env.CORS_ORIGINS || "http://localhost:5173")
  .split(",")
  .map((x) => x.trim().replace(/\/$/, ""));
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || allowed.includes(origin)) return cb(null, true);
      cb(new Error("CORS origin denied"));
    },
  }),
);

const readingSchema = new mongoose.Schema(
  {
    deviceId: { type: String, default: "ESP32-01" },
    distance: { type: Number, default: null },
    sensorOk: { type: Boolean, default: true },
    health: { type: Number, default: 100 },
    mode: { type: String, default: "LOCKED" },
    ammo: { type: Number, default: 10 },
    temperature: { type: Number, default: null },
    humidity: { type: Number, default: null },
    source: { type: String, enum: ["device", "demo"], default: "device" },
    timestamp: { type: Date, default: Date.now },
  },
  { versionKey: false },
);
readingSchema.index({ timestamp: -1 });
const eventSchema = new mongoose.Schema(
  {
    id: { type: String, default: () => randomUUID() },
    deviceId: { type: String, default: "ESP32-01" },
    type: { type: String, required: true },
    message: { type: String, default: "" },
    severity: {
      type: String,
      enum: ["info", "warning", "critical"],
      default: "info",
    },
    source: {
      type: String,
      enum: ["device", "dashboard", "demo"],
      default: "device",
    },
    timestamp: { type: Date, default: Date.now },
  },
  { versionKey: false },
);
eventSchema.index({ timestamp: -1 });
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    trim: true,
    lowercase: true,
  },
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    trim: true,
  },
  passwordHash: { type: String },
  password: { type: String },
  role: { type: String, default: "operator" },
  createdAt: { type: Date, default: Date.now },
});
const Reading =
  mongoose.models.Reading || mongoose.model("Reading", readingSchema);
const Event = mongoose.models.Event || mongoose.model("Event", eventSchema);
const User = mongoose.models.User || mongoose.model("User", userSchema);
let connecting;
export async function connectDb() {
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI not configured");
  if (mongoose.connection.readyState === 1) return mongoose.connection;
  connecting ||= mongoose
    .connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 7000 })
    .then((conn) => {
      console.log(`MongoDB connected (database: ${conn.connection.name})`);
      return conn.connection;
    })
    .finally(() => {
      connecting = null;
    });
  return connecting;
}
async function db(req, res, next) {
  try {
    await connectDb();
    next();
  } catch (e) {
    res
      .status(503)
      .json({
        error: "Database unavailable",
        detail: process.env.NODE_ENV === "production" ? undefined : e.message,
      });
  }
}
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
const secret = () => process.env.JWT_SECRET;
function auth(req, res, next) {
  try {
    if (!secret())
      return res.status(503).json({ error: "JWT_SECRET not configured" });
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    req.user = jwt.verify(token, secret());
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}
function device(req, res, next) {
  const expected = process.env.DEVICE_TOKEN;
  if (!expected)
    return res.status(503).json({ error: "DEVICE_TOKEN not configured" });
  if (req.header("x-device-token") !== expected)
    return res.status(401).json({ error: "Invalid device token" });
  next();
}
const number = (v, min, max) =>
  typeof v === "number" && Number.isFinite(v) && v >= min && v <= max;
app.get("/api/health", (_req, res) =>
  res.json({
    ok: true,
    service: "AEGIS-X API",
    time: new Date().toISOString(),
  }),
);
app.get("/api/db-status", async (_req, res) => {
  if (!process.env.MONGODB_URI)
    return res
      .status(503)
      .json({
        connected: false,
        message:
          "MONGODB_URI missing: configure backend/.env or Vercel environment variables",
      });
  try {
    await connectDb();
    await mongoose.connection.db.admin().ping();
    return res.json({
      connected: true,
      database: mongoose.connection.name,
      collections: ["users", "readings", "events"],
    });
  } catch (e) {
    return res
      .status(503)
      .json({
        connected: false,
        message:
          process.env.NODE_ENV === "production"
            ? "Database connection failed"
            : e.message,
      });
  }
});
const issueAuth = (u) => ({
  token: jwt.sign(
    {
      sub: u.id,
      email: u.email,
      role: u.role || "operator",
    },
    secret(),
    { expiresIn: "7d" },
  ),
  email: u.email,
  user: {
    id: u.id,
    email: u.email,
    role: u.role || "operator",
  },
});
const normalizeEvent = (e) => ({
  ...e,
  deviceId: e.deviceId || e.device || "ESP32-01",
  severity: e.severity || "info",
  timestamp: e.timestamp || e.at || null,
});
app.post(
  "/api/auth/login",
  db,
  wrap(async (req, res) => {
    const email =
      typeof req.body.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";
    const password = String(req.body.password || "");
    if (!secret())
      return res.status(503).json({ error: "JWT_SECRET not configured" });
    if (!/^\S+@\S+\.\S+$/.test(email) || !password)
      return res.status(400).json({ error: "Valid email and password required" });
    const u = await User.findOne({ email });
    const hash = u?.passwordHash || u?.password;
    if (!u || typeof hash !== "string" || !(await bcrypt.compare(password, hash)))
      return res.status(401).json({ error: "Invalid credentials" });
    res.json(issueAuth(u));
  }),
);
app.get(
  "/api/auth/me",
  auth,
  db,
  wrap(async (req, res) => {
    const u = await User.findById(req.user.sub)
      .select("email role createdAt")
      .lean();
    if (!u) return res.status(401).json({ error: "Unauthorized" });
    res.json({
      id: String(u._id),
      email: u.email,
      role: u.role || "operator",
      createdAt: u.createdAt,
    });
  }),
);
app.get(
  "/api/dashboard",
  auth,
  db,
  wrap(async (req, res) => {
    const [latest, history, rawEvents, totalReadings, totalEvents] =
      await Promise.all([
        Reading.findOne().sort({ timestamp: -1 }).lean(),
        Reading.find().sort({ timestamp: -1 }).limit(120).lean(),
        Event.find().sort({ timestamp: -1, at: -1 }).limit(80).lean(),
        Reading.countDocuments(),
        Event.countDocuments(),
      ]);
    const events = rawEvents.map(normalizeEvent);
    const recent = history.slice(0, 30);
    const avgHealth = recent.length
      ? Math.round(recent.reduce((s, x) => s + x.health, 0) / recent.length)
      : null;
    res.json({
      latest,
      history: history.reverse(),
      events,
      stats: {
        totalReadings,
        totalEvents,
        avgHealth,
        faults: events.filter((e) => e.severity !== "info").length,
      },
    });
  }),
);
app.get(
  "/api/readings",
  auth,
  db,
  wrap(async (req, res) =>
    res.json(await Reading.find().sort({ timestamp: -1 }).limit(500).lean()),
  ),
);
app.get(
  "/api/events",
  auth,
  db,
  wrap(async (req, res) =>
    res.json(
      (await Event.find().sort({ timestamp: -1, at: -1 }).limit(500).lean()).map(
        normalizeEvent,
      ),
    ),
  ),
);
app.post(
  "/api/readings",
  device,
  db,
  wrap(async (req, res) => {
    const b = req.body;
    if (
      b.distance !== null &&
      b.distance !== undefined &&
      !number(b.distance, 0, 10000)
    )
      return res.status(400).json({ error: "Invalid distance" });
    if (b.ammo !== undefined && !number(b.ammo, 0, 1000))
      return res.status(400).json({ error: "Invalid ammo" });
    const sensorOk = b.sensorOk !== false;
    const health = number(b.health, 0, 100) ? b.health : sensorOk ? 100 : 0;
    const r = await Reading.create({
      deviceId: String(b.deviceId || "ESP32-01").slice(0, 60),
      distance: b.distance ?? null,
      sensorOk,
      health,
      mode: String(b.mode || "LOCKED").slice(0, 30),
      ammo: b.ammo ?? 10,
      temperature: b.temperature ?? null,
      humidity: b.humidity ?? null,
      source: "device",
    });
    res.status(201).json({ id: r.id });
  }),
);
app.post(
  "/api/events",
  device,
  db,
  wrap(async (req, res) => {
    const b = req.body;
    if (!b.type || typeof b.type !== "string")
      return res.status(400).json({ error: "Event type required" });
    const e = await Event.create({
      deviceId: String(b.deviceId || "ESP32-01").slice(0, 60),
      type: b.type.slice(0, 60),
      message: String(b.message || "").slice(0, 300),
      severity: ["info", "warning", "critical"].includes(b.severity)
        ? b.severity
        : "info",
      source: "device",
    });
    res.status(201).json({ id: e.id });
  }),
);
// Dashboard demonstration controls affect DEMO DATA ONLY; they do not command physical equipment.
app.post(
  "/api/demo/step",
  auth,
  db,
  wrap(async (req, res) => {
    const action = String(req.body.action || "");
    if (
      ![
        "normal",
        "fault",
        "recover",
        "toggle",
        "simulate",
        "reload",
        "reset",
      ].includes(action)
    )
      return res.status(400).json({ error: "Invalid demo action" });
    const prev = await Reading.findOne({ source: "demo" })
      .sort({ timestamp: -1 })
      .lean();
    let state = {
      distance: prev?.distance ?? 35,
      sensorOk: prev?.sensorOk ?? true,
      health: prev?.health ?? 100,
      mode: prev?.mode ?? "LOCKED",
      ammo: prev?.ammo ?? 10,
    };
    let msg = "";
    let severity = "info";
    if (action === "normal") {
      state.distance = Math.round((25 + Math.random() * 45) * 10) / 10;
      state.sensorOk = true;
      state.health = 100;
      msg = "Normal sensor sample";
    }
    if (action === "fault") {
      state.sensorOk = false;
      state.health = 0;
      state.mode = "FAULT LOCK";
      state.distance = null;
      msg = "Simulated sensor timeout";
      severity = "critical";
    }
    if (action === "recover") {
      state.sensorOk = true;
      state.health = 100;
      state.mode = "LOCKED";
      state.distance = 35;
      msg = "Sensor restored; manual unlock required";
    }
    if (action === "toggle") {
      if (!state.sensorOk)
        return res
          .status(409)
          .json({ error: "Sensor fault: demo training locked" });
      state.mode = state.mode === "TRAINING" ? "LOCKED" : "TRAINING";
      msg = `Demo mode: ${state.mode}`;
    }
    if (action === "simulate") {
      if (!state.sensorOk || state.mode !== "TRAINING" || state.ammo <= 0)
        return res
          .status(409)
          .json({ error: "Demo locked or virtual counter empty" });
      state.ammo--;
      msg = "Virtual training action";
    }
    if (action === "reload") {
      state.ammo = 10;
      msg = "Virtual counter reset";
    }
    if (action === "reset") {
      state = {
        distance: 35,
        sensorOk: true,
        health: 100,
        mode: "LOCKED",
        ammo: 10,
      };
      msg = "Demo reset";
    }
    const [r, e] = await Promise.all([
      Reading.create({ ...state, source: "demo", deviceId: "DEMO-01" }),
      Event.create({
        deviceId: "DEMO-01",
        type: action.toUpperCase(),
        message: msg,
        severity,
        source: "demo",
      }),
    ]);
    res.json({ reading: r, event: e });
  }),
);
app.use((err, req, res, next) => {
  console.error(err);
  if (err?.code === 11000)
    return res.status(409).json({ error: "Already exists" });
  res.status(500).json({ error: "Server error" });
});
export default app;
