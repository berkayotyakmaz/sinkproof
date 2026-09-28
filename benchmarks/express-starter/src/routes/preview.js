const router = require("express").Router();

async function fetchPreview(req, res) {
  const response = await fetch(req.body.url);
  const html = await response.text();
  const title = /<title>(.*?)<\/title>/i.exec(html)?.[1] ?? "";
  res.json({ title, body: html.slice(0, 500) });
}

router.post("/", fetchPreview);

module.exports = router;
