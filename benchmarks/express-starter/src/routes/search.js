const router = require("express").Router();
const { query } = require("../db");

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function searchProducts(req, res) {
  const rows = await query(`SELECT id, name, price FROM products WHERE name LIKE '%${req.query.q}%'`);
  res.json(rows);
}

async function searchUsers(req, res) {
  const rows = await query("SELECT id, display_name FROM users WHERE display_name LIKE ?", [`%${req.query.q}%`]);
  res.json(rows);
}

function renderSearch(req, res) {
  res.send(`<html><body><h1>Results for ${req.query.q}</h1></body></html>`);
}

async function renderProfile(req, res) {
  const rows = await query("SELECT display_name, bio FROM users WHERE id = ?", [req.params.id]);
  if (rows.length === 0) return res.sendStatus(404);
  res.send(`<html><body><h1>${escapeHtml(rows[0].display_name)}</h1><p>${escapeHtml(rows[0].bio)}</p></body></html>`);
}

router.get("/products", searchProducts);
router.get("/users", searchUsers);
router.get("/page", renderSearch);
router.get("/profile/:id", renderProfile);

module.exports = router;
