import jwt from "jsonwebtoken";

export function requireDashboardAuth(req, res, next) {
  try {
    const secret = process.env.JWT_SECRET;

    if (!secret) {
      return res.status(503).json({
        error: "JWT_SECRET not configured",
      });
    }

    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");

    if (!token) {
      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    req.user = jwt.verify(token, secret);
    next();
  } catch {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }
}

export default requireDashboardAuth;
