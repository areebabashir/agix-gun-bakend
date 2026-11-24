
import * as tf from "@tensorflow/tfjs";

const MIN_SAMPLES = 10;
const MAX_SAMPLES = 100;
const MIN_STD = 2;

export function analyzeAnomaly(currentDistance, history = []) {
  // Sensor ki invalid reading
  if (
    typeof currentDistance !== "number" ||
    !Number.isFinite(currentDistance) ||
    currentDistance < 0
  ) {
    return {
      anomaly: true,
      score: 100,
      confidence: "rule-based",
      status: "SENSOR_FAULT",
      message: "Invalid sensor reading",
    };
  }

  // Historical normal readings filter karo
  const samples = history
    .filter(
      (r) =>
        r.sensorOk === true &&
        typeof r.distance === "number" &&
        Number.isFinite(r.distance) &&
        r.distance >= 0
    )
    .slice(-MAX_SAMPLES)
    .map((r) => r.distance);

  // Model ko sufficient data chahiye
  if (samples.length < MIN_SAMPLES) {
    return {
      anomaly: false,
      score: 0,
      confidence: "insufficient-data",
      status: "LEARNING",
      message: `Collecting samples (${samples.length}/${MIN_SAMPLES})`,
    };
  }

  // TensorFlow.js tensor calculations
  const tensor = tf.tensor1d(samples);

  let mean;
  let std;

  try {
    mean = tf.mean(tensor).dataSync()[0];

    const varianceTensor = tf.moments(tensor).variance;
    const variance = varianceTensor.dataSync()[0];

    varianceTensor.dispose();

    std = Math.max(Math.sqrt(variance), MIN_STD);
  } finally {
    tensor.dispose();
  }

  // Distance from normal pattern
  const zScore = Math.abs(currentDistance - mean) / std;

  const anomaly = zScore >= 3;

  const score = Math.min(
    100,
    Math.round((zScore / 5) * 100)
  );

  return {
    anomaly,
    score,
    confidence: "statistical-baseline",
    status: anomaly ? "ANOMALY" : "NORMAL",
    message: anomaly
      ? "Unusual distance pattern detected"
      : "Sensor reading within learned range",
    baseline: {
      mean: Number(mean.toFixed(2)),
      std: Number(std.toFixed(2)),
      samples: samples.length,
    },
  };
}
