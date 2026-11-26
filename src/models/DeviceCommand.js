import mongoose from "mongoose";

const deviceCommandSchema = new mongoose.Schema(
  {
    deviceId: {
      type: String,
      required: true,
      index: true,
    },
    command: {
      type: String,
      enum: [
        "ENABLE_TRAINING",
        "LOCK_SYSTEM",
        "RESET_COUNTER",
        "EMERGENCY_LOCK",
      ],
      required: true,
    },
    status: {
      type: String,
      enum: ["pending", "delivered"],
      default: "pending",
    },
  },
  { timestamps: true }
);

deviceCommandSchema.index({ deviceId: 1, status: 1, createdAt: 1 });

const DeviceCommand =
  mongoose.models.DeviceCommand ||
  mongoose.model("DeviceCommand", deviceCommandSchema);

export default DeviceCommand;
