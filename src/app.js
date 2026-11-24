
import "dotenv/config";
import { randomUUID } from "crypto";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { analyzeSensorHealth } from "./ai/sensorHealth.js";

// =====================================
// EXPRESS CONFIGURATION
// =====================================

const app = express();

app.use(express.json({ limit: "200kb" }));

const allowed = (
  process.env.CORS_ORIGINS || "http://localhost:5173"
)
  .split(",")
  .map((x) => x.trim().replace(/\/$/, ""));

app.use(
  cors({
    origin(origin, cb) {
      if (!origin || allowed.includes(origin)) {
        return cb(null, true);
      }

      cb(new Error("CORS origin denied"));
    },
  })
);

// =====================================
// MONGODB SCHEMAS
// =====================================

const readingSchema = new mongoose.Schema(
  {
    deviceId: {
      type: String,
      default: "ESP32-01",
    },

    distance: {
      type: Number,
      default: null,
    },

    sensorOk: {
      type: Boolean,
      default: true,
    },

    health: {
      type: Number,
      default: 100,
    },

    mode: {
      type: String,
      default: "LOCKED",
    },

    ammo: {
      type: Number,
      default: 10,
    },

    temperature: {
      type: Number,
      default: null,
    },

    humidity: {
      type: Number,
      default: null,
    },

    source: {
      type: String,
      enum: ["device", "demo"],
      default: "device",
    },

    // ---------- AI FIELDS ----------

    aiHealthScore: {
      type: Number,
      default: null,
    },

    aiAnomalyScore: {
      type: Number,
      default: null,
    },

    aiStatus: {
      type: String,
      default: "PENDING",
    },

    aiAnomalyDetected: {
      type: Boolean,
      default: false,
    },

    aiMessage: {
      type: String,
      default: "",
    },

    aiRecommendation: {
      type: String,
      default: "",
    },

    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  { versionKey: false }
);

readingSchema.index({ timestamp: -1 });

// =====================================
// EVENT SCHEMA
// =====================================

const eventSchema = new mongoose.Schema(
  {
    id: {
      type: String,
      default: () => randomUUID(),
    },

    deviceId: {
      type: String,
      default: "ESP32-01",
    },

    type: {
      type: String,
      required: true,
    },

    message: {
      type: String,
      default: "",
    },

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

    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  { versionKey: false }
);

eventSchema.index({ timestamp: -1 });

// =====================================
// USER SCHEMA
// =====================================

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

  passwordHash: {
    type: String,
  },

  password: {
    type: String,
  },

  role: {
    type: String,
    default: "operator",
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// =====================================
// MONGOOSE MODELS
// =====================================

const Reading =
  mongoose.models.Reading ||
  mongoose.model("Reading", readingSchema);

const Event =
  mongoose.models.Event ||
  mongoose.model("Event", eventSchema);

const User =
  mongoose.models.User ||
  mongoose.model("User", userSchema);

// =====================================
// DATABASE CONNECTION
// =====================================

let connecting;

export async function connectDb() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI not configured");
  }

  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  connecting ||= mongoose
    .connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 7000,
    })
    .then((conn) => {
      console.log(
        `MongoDB connected (database: ${conn.connection.name})`
      );

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
  } catch (error) {
    return res.status(503).json({
      error: "Database unavailable",
      detail:
        process.env.NODE_ENV === "production"
          ? undefined
          : error.message,
    });
  }
}

// =====================================
// ASYNC ERROR WRAPPER
// =====================================

const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// =====================================
// AUTHENTICATION
// =====================================

const secret = () => process.env.JWT_SECRET;

function auth(req, res, next) {
  try {
    if (!secret()) {
      return res.status(503).json({
        error: "JWT_SECRET not configured",
      });
    }

    const token = (
      req.headers.authorization || ""
    ).replace(/^Bearer\s+/i, "");

    req.user = jwt.verify(token, secret());

    next();
  } catch {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }
}

// =====================================
// ESP32 DEVICE AUTHENTICATION
// =====================================

function device(req, res, next) {
  const expected = process.env.DEVICE_TOKEN;

  if (!expected) {
    return res.status(503).json({
      error: "DEVICE_TOKEN not configured",
    });
  }

  if (req.header("x-device-token") !== expected) {
    return res.status(401).json({
      error: "Invalid device token",
    });
  }

  next();
}

// =====================================
// VALIDATION
// =====================================

const number = (value, min, max) =>
  typeof value === "number" &&
  Number.isFinite(value) &&
  value >= min &&
  value <= max;

// =====================================
// ROOT API
// =====================================

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "AEGIS-X API",
    health: "/api/health",
    dbStatus: "/api/db-status",
    time: new Date().toISOString(),
  });
});

// =====================================
// HEALTH CHECK
// =====================================

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "AEGIS-X API",
    time: new Date().toISOString(),
  });
});

// =====================================
// DATABASE STATUS
// =====================================

app.get("/api/db-status", async (_req, res) => {
  if (!process.env.MONGODB_URI) {
    return res.status(503).json({
      connected: false,
      message:
        "MONGODB_URI missing: configure backend/.env or Vercel environment variables",
    });
  }

  try {
    await connectDb();

    await mongoose.connection.db.admin().ping();

    return res.json({
      connected: true,
      database: mongoose.connection.name,
      collections: ["users", "readings", "events"],
    });
  } catch (error) {
    return res.status(503).json({
      connected: false,
      message:
        process.env.NODE_ENV === "production"
          ? "Database connection failed"
          : error.message,
    });
  }
});

// =====================================
// JWT TOKEN RESPONSE
// =====================================

const issueAuth = (user) => ({
  token: jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role || "operator",
    },
    secret(),
    { expiresIn: "7d" }
  ),

  email: user.email,

  user: {
    id: user.id,
    email: user.email,
    role: user.role || "operator",
  },
});

// =====================================
// NORMALIZE EVENTS
// =====================================

const normalizeEvent = (event) => ({
  ...event,
  deviceId:
    event.deviceId || event.device || "ESP32-01",
  severity: event.severity || "info",
  timestamp:
    event.timestamp || event.at || null,
});

// =====================================
// LOGIN API
// =====================================

app.post(
  "/api/auth/login",
  db,
  wrap(async (req, res) => {
    const email =
      typeof req.body.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";

    const password = String(
      req.body.password || ""
    );

    if (!secret()) {
      return res.status(503).json({
        error: "JWT_SECRET not configured",
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(email) || !password) {
      return res.status(400).json({
        error: "Valid email and password required",
      });
    }

    const user = await User.findOne({ email });

    const hash =
      user?.passwordHash || user?.password;

    if (
      !user ||
      typeof hash !== "string" ||
      !(await bcrypt.compare(password, hash))
    ) {
      return res.status(401).json({
        error: "Invalid credentials",
      });
    }

    return res.json(issueAuth(user));
  })
);

// =====================================
// CURRENT USER
// =====================================

app.get(
  "/api/auth/me",
  auth,
  db,
  wrap(async (req, res) => {
    const user = await User.findById(
      req.user.sub
    )
      .select("email role createdAt")
      .lean();

    if (!user) {
      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    return res.json({
      id: String(user._id),
      email: user.email,
      role: user.role || "operator",
      createdAt: user.createdAt,
    });
  })
);

// =====================================
// DASHBOARD API
// =====================================

app.get(
  "/api/dashboard",
  auth,
  db,
  wrap(async (req, res) => {
    const [
      latest,
      history,
      rawEvents,
      totalReadings,
      totalEvents,
    ] = await Promise.all([
      Reading.findOne()
        .sort({ timestamp: -1 })
        .lean(),

      Reading.find()
        .sort({ timestamp: -1 })
        .limit(120)
        .lean(),

      Event.find()
        .sort({ timestamp: -1, at: -1 })
        .limit(80)
        .lean(),

      Reading.countDocuments(),

      Event.countDocuments(),
    ]);

    const events = rawEvents.map(normalizeEvent);

    const recent = history.slice(0, 30);

    const avgHealth = recent.length
      ? Math.round(
          recent.reduce(
            (sum, item) => sum + item.health,
            0
          ) / recent.length
        )
      : null;

    return res.json({
      latest,
      history: history.reverse(),
      events,

      stats: {
        totalReadings,
        totalEvents,
        avgHealth,

        faults: events.filter(
          (event) => event.severity !== "info"
        ).length,
      },
    });
  })
);

// =====================================
// GET SENSOR READINGS
// =====================================

app.get(
  "/api/readings",
  auth,
  db,
  wrap(async (req, res) => {
    const readings = await Reading.find()
      .sort({ timestamp: -1 })
      .limit(500)
      .lean();

    return res.json(readings);
  })
);

// =====================================
// GET EVENTS
// =====================================

app.get(
  "/api/events",
  auth,
  db,
  wrap(async (req, res) => {
    const events = await Event.find()
      .sort({ timestamp: -1, at: -1 })
      .limit(500)
      .lean();

    return res.json(
      events.map(normalizeEvent)
    );
  })
);

// =====================================
// ESP32 TELEMETRY + AI ENGINE
// =====================================

app.post(
  "/api/readings",
  device,
  db,
  wrap(async (req, res) => {
    const body = req.body || {};

    // ---------- VALIDATE DISTANCE ----------

    if (
      body.distance !== null &&
      body.distance !== undefined &&
      !number(body.distance, 0, 10000)
    ) {
      return res.status(400).json({
        error: "Invalid distance",
      });
    }

    // ---------- VALIDATE AMMO ----------

    if (
      body.ammo !== undefined &&
      !number(body.ammo, 0, 1000)
    ) {
      return res.status(400).json({
        error: "Invalid ammo",
      });
    }

    // ---------- DEVICE INFORMATION ----------

    const deviceId = String(
      body.deviceId || "ESP32-01"
    ).slice(0, 60);

    const sensorOk = body.sensorOk !== false;

    const current = {
      deviceId,

      distance: body.distance ?? null,

      sensorOk,

      health: number(body.health, 0, 100)
        ? body.health
        : sensorOk
          ? 100
          : 0,

      mode: String(
        body.mode || "LOCKED"
      ).slice(0, 30),

      ammo: body.ammo ?? 10,

      temperature:
        body.temperature ?? null,

      humidity:
        body.humidity ?? null,

      source: "device",
    };

    // =====================================
    // AI SMART SENSOR ANALYSIS
    // =====================================

    let ai = {
      healthScore: null,
      anomalyScore: null,
      status: "UNAVAILABLE",
      anomalyDetected: false,
      message: "AI analysis unavailable",
      recommendation: "Review server logs",
    };

    try {
      // Get historical readings
      // from the same ESP32 device

      const history = await Reading.find({
        deviceId,
        source: "device",
        sensorOk: true,
        distance: { $ne: null },
      })
        .sort({ timestamp: -1 })
        .limit(100)
        .select("distance sensorOk")
        .lean();

      // Analyze using TensorFlow.js
      ai = analyzeSensorHealth(
        current,
        history.reverse()
      );

      console.log(
        `[AI] ${deviceId}: ${ai.status}`
      );

    } catch (error) {
      console.error(
        "[AI] Analysis failed:",
        error
      );
    }

    // =====================================
    // SAVE SENSOR + AI DATA
    // =====================================

    const reading = await Reading.create({
      ...current,

      aiHealthScore: ai.healthScore,

      aiAnomalyScore: ai.anomalyScore,

      aiStatus: ai.status,

      aiAnomalyDetected:
        ai.anomalyDetected,

      aiMessage: ai.message,

      aiRecommendation:
        ai.recommendation,
    });

    // =====================================
    // AUTOMATIC AI ALERT
    // =====================================

    if (ai.anomalyDetected) {
      try {
        // Avoid repeated alerts while
        // the same anomaly is active.

        const previous = await Reading.findOne({
          deviceId,
          source: "device",
          _id: { $ne: reading._id },
        })
          .sort({ timestamp: -1 })
          .select("aiAnomalyDetected")
          .lean();

        if (!previous?.aiAnomalyDetected) {
          await Event.create({
            deviceId,

            type: "AI_ANOMALY",

            message: String(
              ai.message || "Anomaly detected"
            ).slice(0, 300),

            severity:
              ai.status === "CRITICAL"
                ? "critical"
                : "warning",

            source: "device",
          });

          console.log(
            "[AI] Anomaly alert created"
          );
        }

      } catch (error) {
        console.error(
          "[AI] Event creation failed:",
          error
        );
      }
    }

    // =====================================
    // SEND RESPONSE TO ESP32
    // =====================================

    return res.status(201).json({
      id: reading.id,

      ai: {
        healthScore:
          ai.healthScore,

        anomalyScore:
          ai.anomalyScore,

        status:
          ai.status,

        anomalyDetected:
          ai.anomalyDetected,

        message:
          ai.message,

        recommendation:
          ai.recommendation,
      },
    });
  })
);

// =====================================
// ESP32 EVENTS API
// =====================================

app.post(
  "/api/events",
  device,
  db,
  wrap(async (req, res) => {
    const body = req.body || {};

    if (
      !body.type ||
      typeof body.type !== "string"
    ) {
      return res.status(400).json({
        error: "Event type required",
      });
    }

    const event = await Event.create({
      deviceId: String(
        body.deviceId || "ESP32-01"
      ).slice(0, 60),

      type: body.type.slice(0, 60),

      message: String(
        body.message || ""
      ).slice(0, 300),

      severity: [
        "info",
        "warning",
        "critical",
      ].includes(body.severity)
        ? body.severity
        : "info",

      source: "device",
    });

    return res.status(201).json({
      id: event.id,
    });
  })
);

// =====================================
// DASHBOARD DEMO CONTROLS
// Demo only: no physical equipment control
// =====================================

app.post(
  "/api/demo/step",
  auth,
  db,
  wrap(async (req, res) => {
    const action = String(
      req.body.action || ""
    );

    const allowedActions = [
      "normal",
      "fault",
      "recover",
      "toggle",
      "simulate",
      "reload",
      "reset",
    ];

    if (!allowedActions.includes(action)) {
      return res.status(400).json({
        error: "Invalid demo action",
      });
    }

    const prev = await Reading.findOne({
      source: "demo",
    })
      .sort({ timestamp: -1 })
      .lean();

    let state = {
      distance: prev?.distance ?? 35,
      sensorOk: prev?.sensorOk ?? true,
      health: prev?.health ?? 100,
      mode: prev?.mode ?? "LOCKED",
      ammo: prev?.ammo ?? 10,
    };

    let message = "";
    let severity = "info";

    // ---------- NORMAL ----------

    if (action === "normal") {
      state.distance =
        Math.round(
          (25 + Math.random() * 45) * 10
        ) / 10;

      state.sensorOk = true;
      state.health = 100;

      message = "Normal sensor sample";
    }

    // ---------- FAULT ----------

    if (action === "fault") {
      state.sensorOk = false;
      state.health = 0;
      state.mode = "FAULT LOCK";
      state.distance = null;

      message = "Simulated sensor timeout";
      severity = "critical";
    }

    // ---------- RECOVER ----------

    if (action === "recover") {
      state.sensorOk = true;
      state.health = 100;
      state.mode = "LOCKED";
      state.distance = 35;

      message =
        "Sensor restored; manual unlock required";
    }

    // ---------- TOGGLE ----------

    if (action === "toggle") {
      if (!state.sensorOk) {
        return res.status(409).json({
          error:
            "Sensor fault: demo training locked",
        });
      }

      state.mode =
        state.mode === "TRAINING"
          ? "LOCKED"
          : "TRAINING";

      message = `Demo mode: ${state.mode}`;
    }

    // ---------- SIMULATE ----------

    if (action === "simulate") {
      if (
        !state.sensorOk ||
        state.mode !== "TRAINING" ||
        state.ammo <= 0
      ) {
        return res.status(409).json({
          error:
            "Demo locked or virtual counter empty",
        });
      }

      state.ammo--;

      message =
        "Virtual training action";
    }

    // ---------- RELOAD ----------

    if (action === "reload") {
      state.ammo = 10;

      message =
        "Virtual counter reset";
    }

    // ---------- RESET ----------

    if (action === "reset") {
      state = {
        distance: 35,
        sensorOk: true,
        health: 100,
        mode: "LOCKED",
        ammo: 10,
      };

      message = "Demo reset";
    }

    // ---------- SAVE DEMO DATA ----------

    const [reading, event] =
      await Promise.all([
        Reading.create({
          ...state,
          source: "demo",
          deviceId: "DEMO-01",
        }),

        Event.create({
          deviceId: "DEMO-01",

          type: action.toUpperCase(),

          message,

          severity,

          source: "demo",
        }),
      ]);

    return res.json({
      reading,
      event,
    });
  })
);

// =====================================
// GLOBAL ERROR HANDLER
// =====================================

app.use((err, req, res, next) => {
  console.error(err);

  if (err?.code === 11000) {
    return res.status(409).json({
      error: "Already exists",
    });
  }

  return res.status(500).json({
    error: "Server error",
  });
});

// =====================================
// EXPORT EXPRESS APP
// =====================================

export default app;
