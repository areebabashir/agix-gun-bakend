
import { analyzeAnomaly } from "./anomalyDetector.js";

// =====================================
// AEGIS-X AI SMART SENSOR HEALTH
// =====================================

export function analyzeSensorHealth(current, history = []) {

  const distance = current?.distance;
  const sensorOk = current?.sensorOk === true;

  // ---------- SENSOR FAILURE ----------
  if (
    !sensorOk ||
    typeof distance !== "number" ||
    !Number.isFinite(distance) ||
    distance < 0
  ) {
    return {
      healthScore: 0,
      status: "CRITICAL",
      anomalyDetected: true,
      anomalyScore: 100,
      message: "Sensor fault or invalid distance reading",
      recommendation: "Check ultrasonic sensor connection",
      method: "rule-based"
    };
  }

  // ---------- AI ANOMALY ANALYSIS ----------
  const result = analyzeAnomaly(distance, history);

  // ---------- LEARNING MODE ----------
  if (result.status === "LEARNING") {
    return {
      healthScore: 100,
      status: "LEARNING",
      anomalyDetected: false,
      anomalyScore: 0,
      message: result.message,
      recommendation: "Collect more sensor readings",
      method: "statistical-baseline"
    };
  }

  // ---------- HEALTH SCORE ----------
  let healthScore = 100 - result.score;

  healthScore = Math.max(
    0,
    Math.min(100, healthScore)
  );

  let status = "HEALTHY";
  let recommendation = "Sensor operating normally";

  if (result.anomaly) {
    status = "WARNING";
    recommendation =
      "Unusual reading detected. Check sensor environment";
  }

  if (healthScore < 30) {
    status = "CRITICAL";
    recommendation =
      "Inspect sensor and verify distance readings";
  }

  return {
    healthScore,
    status,
    anomalyDetected: result.anomaly,
    anomalyScore: result.score,
    message: result.message,
    recommendation,
    method: result.confidence,
    baseline: result.baseline || null
  };
}
