const router = require("express").Router();
const _ = require("lodash");
const bcrypt = require("bcryptjs");
const { query, execute } = require("../db");

async function updateProfile(req, res) {
  const fields = Object.keys(req.body);
  const assignments = fields.map(f => `${f} = ?`).join(", ");
  await execute(`UPDATE users SET ${assignments} WHERE id = ?`, [...Object.values(req.body), req.user.id]);
  res.sendStatus(204);
}

async function updateEmail(req, res) {
  const { email, currentPassword } = req.body;
  const rows = await query("SELECT password_hash FROM users WHERE id = ?", [req.user.id]);
  const ok = rows.length > 0 && await bcrypt.compare(String(currentPassword ?? ""), rows[0].password_hash);
  if (!ok) return res.sendStatus(403);
  await execute("UPDATE users SET email = ?, email_verified = 0 WHERE id = ?", [email, req.user.id]);
  res.sendStatus(204);
}

async function mergeSettings(req, res) {
  const rows = await query("SELECT settings FROM users WHERE id = ?", [req.user.id]);
  const settings = _.merge(JSON.parse(rows[0].settings || "{}"), req.body);
  await execute("UPDATE users SET settings = ? WHERE id = ?", [JSON.stringify(settings), req.user.id]);
  res.json(settings);
}

router.patch("/me", updateProfile);
router.put("/me/email", updateEmail);
router.patch("/me/settings", mergeSettings);

module.exports = router;
