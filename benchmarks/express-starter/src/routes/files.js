const router = require("express").Router();
const path = require("path");

const REPORTS_DIR = path.resolve(__dirname, "..", "..", "reports");

function downloadFile(req, res) {
  res.sendFile(path.join(REPORTS_DIR, req.params.name));
}

function readReport(req, res) {
  const target = path.resolve(REPORTS_DIR, req.params.name);
  if (!target.startsWith(REPORTS_DIR + path.sep)) return res.sendStatus(400);
  res.sendFile(target);
}

router.get("/download/:name", downloadFile);
router.get("/reports/:name", readReport);

module.exports = router;
