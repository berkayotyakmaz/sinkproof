const express = require("express");
const { query } = require("./db");

const app = express();
app.use(express.json());

async function requireUser(req, res, next) {
  const token = req.get("Authorization")?.replace("Bearer ", "");
  if (!token) return res.sendStatus(401);
  const rows = await query("SELECT id, role FROM users WHERE session_token = ?", [token]);
  if (rows.length === 0) return res.sendStatus(401);
  req.user = rows[0];
  next();
}

app.use("/search", require("./routes/search"));
app.use("/auth", require("./routes/auth"));
app.use(requireUser);
app.use("/orders", require("./routes/orders"));
app.use("/users", require("./routes/users"));
app.use("/preview", require("./routes/preview"));
app.use("/coupons", require("./routes/coupons"));
app.use("/files", require("./routes/files"));

app.listen(3000);
