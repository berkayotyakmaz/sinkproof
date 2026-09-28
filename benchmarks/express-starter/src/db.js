const mysql = require("mysql2/promise");

const pool = mysql.createPool({ uri: process.env.DATABASE_URL });

async function query(sql, params = []) {
  const [rows] = await pool.query(sql, params);
  return rows;
}

async function execute(sql, params = []) {
  const [result] = await pool.execute(sql, params);
  return result;
}

module.exports = { query, execute };
