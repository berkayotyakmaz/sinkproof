const router = require("express").Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const { query } = require("../db");

const SECRET = process.env.JWT_SECRET;
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });
const accountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  keyGenerator: req => String(req.body?.email ?? "").toLowerCase(),
});

async function checkCredentials(email, password) {
  const rows = await query("SELECT id, password_hash FROM users WHERE email = ?", [email]);
  if (rows.length === 0) return null;
  return (await bcrypt.compare(String(password ?? ""), rows[0].password_hash)) ? rows[0] : null;
}

async function login(req, res) {
  const user = await checkCredentials(req.body.email, req.body.password);
  if (!user) return res.sendStatus(401);
  res.json({ token: jwt.sign({ sub: user.id }, SECRET, { algorithm: "HS256", expiresIn: "1h" }) });
}

async function loginV2(req, res) {
  const user = await checkCredentials(req.body.email, req.body.password);
  if (!user) return res.sendStatus(401);
  res.json({ token: jwt.sign({ sub: user.id }, SECRET, { algorithm: "HS256", expiresIn: "1h" }) });
}

function verifyToken(req, res, next) {
  const claims = jwt.decode(req.get("Authorization")?.replace("Bearer ", "") ?? "");
  if (!claims) return res.sendStatus(401);
  req.user = { id: claims.sub };
  next();
}

function verifyTokenStrict(req, res, next) {
  try {
    const claims = jwt.verify(req.get("Authorization")?.replace("Bearer ", "") ?? "", SECRET, { algorithms: ["HS256"] });
    req.user = { id: claims.sub };
    next();
  } catch {
    res.sendStatus(401);
  }
}

function redirectAfterLogin(req, res) {
  res.redirect(req.query.returnUrl || "/");
}

function redirectSafe(req, res) {
  const target = String(req.query.returnUrl || "/");
  const sameOrigin = target.startsWith("/") && !target.startsWith("//") && !target.startsWith("/\\");
  res.redirect(sameOrigin ? target : "/");
}

router.post("/login", login);
router.post("/v2/login", loginLimiter, accountLimiter, loginV2);
router.get("/me", verifyToken, (req, res) => res.json(req.user));
router.get("/v2/me", verifyTokenStrict, (req, res) => res.json(req.user));
router.get("/continue", redirectAfterLogin);
router.get("/v2/continue", redirectSafe);

module.exports = router;
