import express from "express";
import mongoose from "mongoose";
import DeviceCommand from "../models/DeviceCommand.js";
import requireDashboardAuth from "../middleware/requireDashboardAuth.js";

const router = express.Router();

const TARGET_DEVICE_ID = "AEGIS-X-ESP32";

export const ALLOWED_COMMANDS = [
  "ENABLE_TRAINING",
  "LOCK_SYSTEM",
  "RESET_COUNTER",
  "EMERGENCY_LOCK",
];

function requireDevice(req, res, next) {
  const expected = process.env.DEVICE_TOKEN;

  if (!expected) {
    return res.status(503).json({
      error: "DEVICE_TOKEN not configured",
    });
  }

  const supplied = req.get("x-device-token");

  if (!supplied || supplied !== expected) {
    return res.status(401).json({
      error: "Unauthorized device",
    });
  }

  next();
}

// React dashboard sends a voice/remote command
router.post("/command", requireDashboardAuth, async (req, res) => {
  try {
    const { deviceId, command } = req.body || {};

    if (deviceId !== TARGET_DEVICE_ID || !ALLOWED_COMMANDS.includes(command)) {
      return res.status(400).json({
        error: "Invalid command",
      });
    }

    // Prevent older pending commands executing later
    await DeviceCommand.deleteMany({
      deviceId,
      status: "pending",
    });

    const saved = await DeviceCommand.create({
      deviceId,
      command,
    });

    // Record in audit trail if Event model is registered
    if (mongoose.models.Event) {
      await mongoose.models.Event.create({
        deviceId,
        type: "VOICE_COMMAND",
        message: `Queued command: ${command}`,
        severity: command === "EMERGENCY_LOCK" ? "critical" : "info",
        source: "dashboard",
      }).catch((err) => {
        console.error("[Voice] Event log failed:", err.message);
      });
    }

    return res.status(201).json({
      success: true,
      id: saved._id,
      status: "queued",
      command: saved.command,
      deviceId: saved.deviceId,
      createdAt: saved.createdAt,
    });
  } catch (error) {
    console.error("[Voice] Queue error:", error);
    return res.status(500).json({
      error: "Unable to queue command",
    });
  }
});

// React dashboard fetches recent voice command queue status
router.get("/history", requireDashboardAuth, async (_req, res) => {
  try {
    const commands = await DeviceCommand.find({ deviceId: TARGET_DEVICE_ID })
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    return res.json(commands);
  } catch (error) {
    console.error("[Voice] History fetch error:", error);
    return res.status(500).json({
      error: "Unable to fetch command history",
    });
  }
});

// ESP32 polls for next command
router.get("/next", requireDevice, async (_req, res) => {
  try {
    const command = await DeviceCommand.findOneAndUpdate(
      {
        deviceId: TARGET_DEVICE_ID,
        status: "pending",
      },
      { $set: { status: "delivered" } },
      {
        sort: { createdAt: 1 },
        new: true,
      }
    );

    return res.json({
      command: command?.command || "NONE",
    });
  } catch (error) {
    console.error("[Voice] Command fetch error:", error);
    return res.status(500).json({
      error: "Command fetch failed",
    });
  }
});

export default router;
