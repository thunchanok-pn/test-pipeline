const { Pool } = require("pg");

// Replicate the environment config mapping your server.js uses
const pool = new Pool({
  host: process.env.POSTGRES_HOST,
  port: Number(process.env.POSTGRES_PORT || 5432),
  database: process.env.POSTGRES_DB,
  user: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASSWORD,
  connectionTimeoutMillis: 3000
});

async function runTest() {
  try {
    console.log("Checking database compatibility...");
    
    // Attempt the exact query pattern from server.js to test table compatibility
    const result = await pool.query(
      "SELECT username FROM app_users WHERE username = $1 AND password = $2 AND active = true LIMIT 1",
      ["test_admin", "secure_password"]
    );
    
    console.log(`✅ Postgres 16 Compatibility Verified! Query completed without errors. Found rows: ${result.rowCount}`);
    await pool.end();
    process.exit(0); // Success exit code
  } catch (error) {
    console.error("❌ Database compatibility validation failed!");
    console.error(error.message);
    await pool.end();
    process.exit(1); // Failure exit code
  }
}

runTest();
