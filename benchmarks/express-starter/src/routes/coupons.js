const router = require("express").Router();
const { query, execute } = require("../db");

async function redeemCoupon(req, res) {
  const rows = await query("SELECT id, amount, redeemed_by FROM coupons WHERE code = ?", [req.body.code]);
  const coupon = rows[0];
  if (!coupon || coupon.redeemed_by) return res.status(409).send("Invalid coupon");
  await execute("UPDATE users SET balance = balance + ? WHERE id = ?", [coupon.amount, req.user.id]);
  await execute("UPDATE coupons SET redeemed_by = ? WHERE id = ?", [req.user.id, coupon.id]);
  res.json({ credited: coupon.amount });
}

async function redeemGiftCard(req, res) {
  const result = await execute(
    "UPDATE gift_cards SET redeemed_by = ? WHERE code = ? AND redeemed_by IS NULL",
    [req.user.id, req.body.code]
  );
  if (result.affectedRows === 0) return res.status(409).send("Invalid gift card");
  const rows = await query("SELECT amount FROM gift_cards WHERE code = ?", [req.body.code]);
  await execute("UPDATE users SET balance = balance + ? WHERE id = ?", [rows[0].amount, req.user.id]);
  res.json({ credited: rows[0].amount });
}

router.post("/redeem", redeemCoupon);
router.post("/gift-cards/redeem", redeemGiftCard);

module.exports = router;
