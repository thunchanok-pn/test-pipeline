const crypto = require("crypto");
const fs = require("fs/promises");
const http = require("http");
const path = require("path");
const { URL } = require("url");
const { Client } = require("ldapts");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const CREDENTIALS_FILE = path.join(ROOT, "default-user-passwd.txt");
const LDAP_CONFIG_FILE = path.join(ROOT, "data", "ldap-config.json");
const sessions = new Map();
let dbPool;

const DEFAULT_LDAP_CONFIG = {
  enabled: false,
  url: "ldap://ad.example.com:389",
  baseDn: "DC=example,DC=com",
  bindDn: "",
  bindPassword: "",
  domain: "example.com",
  userFilter: "(|(sAMAccountName={{username}})(userPrincipalName={{username}}))",
  tlsRejectUnauthorized: true
};

const staticTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

async function loadUsers() {
  const contents = await fs.readFile(CREDENTIALS_FILE, "utf8");

  return contents
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && line !== "username:password")
    .map((line) => {
      const separator = line.indexOf(":");
      if (separator === -1) return null;

      return {
        username: line.slice(0, separator),
        password: line.slice(separator + 1)
      };
    })
    .filter(Boolean);
}

async function isValidLogin(username, password) {
  const users = await loadUsers();
  return users.some((user) => user.username === username && user.password === password);
}

function getDatabaseConfig() {
  return {
    host: process.env.POSTGRES_HOST,
    port: Number(process.env.POSTGRES_PORT || 5432),
    database: process.env.POSTGRES_DB,
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD
  };
}

function isDatabaseEnabled() {
  const config = getDatabaseConfig();
  return Boolean(config.host && config.database && config.user && config.password);
}

function getDbPool() {
  if (!isDatabaseEnabled()) {
    return null;
  }

  if (!dbPool) {
    dbPool = new Pool({
      ...getDatabaseConfig(),
      max: 5,
      connectionTimeoutMillis: 3000,
      idleTimeoutMillis: 10000
    });
  }

  return dbPool;
}

async function authenticateWithDatabase(username, password) {
  const pool = getDbPool();

  if (!pool) {
    return false;
  }

  try {
    const result = await pool.query(
      "SELECT username FROM app_users WHERE username = $1 AND password = $2 AND active = true LIMIT 1",
      [username, password]
    );

    return result.rowCount === 1;
  } catch (error) {
    console.warn(`Postgres authentication failed for ${username}: ${error.message}`);
    return false;
  }
}

function isLdapEnabled(config = DEFAULT_LDAP_CONFIG) {
  return Boolean(config.enabled && config.url && (config.baseDn || config.domain));
}

async function loadLdapConfig() {
  try {
    const contents = await fs.readFile(LDAP_CONFIG_FILE, "utf8");
    return { ...DEFAULT_LDAP_CONFIG, ...JSON.parse(contents) };
  } catch (error) {
    if (error.code === "ENOENT") {
      return { ...DEFAULT_LDAP_CONFIG };
    }

    throw error;
  }
}

async function saveLdapConfig(config) {
  await fs.mkdir(path.dirname(LDAP_CONFIG_FILE), { recursive: true });
  await fs.writeFile(LDAP_CONFIG_FILE, JSON.stringify(config, null, 2));
}

function publicLdapConfig(config) {
  const { bindPassword, ...safeConfig } = config;
  return { ...safeConfig, bindPasswordSet: Boolean(bindPassword) };
}

function normalizeLdapConfig(input, previous = DEFAULT_LDAP_CONFIG) {
  const next = {
    enabled: Boolean(input.enabled),
    url: String(input.url || "").trim(),
    baseDn: String(input.baseDn || "").trim(),
    bindDn: String(input.bindDn || "").trim(),
    bindPassword:
      input.bindPassword === undefined || input.bindPassword === ""
        ? previous.bindPassword || ""
        : String(input.bindPassword),
    domain: String(input.domain || "").trim(),
    userFilter: String(input.userFilter || DEFAULT_LDAP_CONFIG.userFilter).trim(),
    tlsRejectUnauthorized: Boolean(input.tlsRejectUnauthorized)
  };

  if (!next.userFilter.includes("{{username}}")) {
    next.userFilter = DEFAULT_LDAP_CONFIG.userFilter;
  }

  return next;
}

function escapeLdapFilterValue(value) {
  return String(value).replace(/[\\*()\0]/g, (character) => {
    const replacements = {
      "\\": "\\5c",
      "*": "\\2a",
      "(": "\\28",
      ")": "\\29",
      "\0": "\\00"
    };

    return replacements[character];
  });
}

function formatDirectBindUsername(username, domain) {
  if (username.includes("@") || username.includes("\\") || username.includes("=")) {
    return username;
  }

  return domain ? `${username}@${domain}` : username;
}

async function authenticateWithLdap(username, password, config) {
  if (!isLdapEnabled(config)) {
    return false;
  }

  const clientOptions = {
    url: config.url,
    timeout: 5000,
    connectTimeout: 5000
  };

  if (config.url.toLowerCase().startsWith("ldaps://")) {
    clientOptions.tlsOptions = {
      rejectUnauthorized: config.tlsRejectUnauthorized
    };
  }

  const client = new Client(clientOptions);

  try {
    if (!config.bindDn || !config.bindPassword) {
      await client.bind(formatDirectBindUsername(username, config.domain), password);
      return true;
    }

    await client.bind(config.bindDn, config.bindPassword);

    const filter = config.userFilter.replaceAll("{{username}}", escapeLdapFilterValue(username));
    const { searchEntries } = await client.search(config.baseDn, {
      scope: "sub",
      filter,
      sizeLimit: 1,
      attributes: ["dn", "cn", "sAMAccountName", "userPrincipalName"]
    });

    const userDn = searchEntries[0]?.dn;
    if (!userDn) {
      return false;
    }

    await client.bind(userDn, password);
    return true;
  } catch (error) {
    console.warn(`LDAP authentication failed for ${username}: ${error.message}`);
    return false;
  } finally {
    try {
      await client.unbind();
    } catch (error) {
      // The connection may already be closed after a failed bind.
    }
  }
}

async function authenticateUser(username, password) {
  if (await isValidLogin(username, password)) {
    return { username, source: "file" };
  }

  if (await authenticateWithDatabase(username, password)) {
    return { username, source: "postgres" };
  }

  const ldapConfig = await loadLdapConfig();
  if (await authenticateWithLdap(username, password, ldapConfig)) {
    return { username, source: "ldap" };
  }

  return null;
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  res.end(JSON.stringify(payload));
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map((cookie) => cookie.trim())
      .filter(Boolean)
      .map((cookie) => {
        const separator = cookie.indexOf("=");
        return [cookie.slice(0, separator), decodeURIComponent(cookie.slice(separator + 1))];
      })
  );
}

function getCurrentUser(req) {
  const token = parseCookies(req).session;
  return token ? sessions.get(token) : null;
}

function requireUser(req, res) {
  const username = getCurrentUser(req);

  if (!username) {
    sendJson(res, 401, { error: "Not authenticated" });
    return null;
  }

  return username;
}

async function readJsonBody(req) {
  let body = "";

  for await (const chunk of req) {
    body += chunk;
    if (body.length > 1_000_000) {
      throw new Error("Request body is too large.");
    }
  }

  return body ? JSON.parse(body) : {};
}

async function serveStatic(res, pathname) {
  const requestedPath = pathname === "/" ? "/index.html" : pathname;
  const filePath = path.normalize(path.join(PUBLIC_DIR, requestedPath));

  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendJson(res, 403, { error: "Forbidden" });
    return;
  }

  try {
    const contents = await fs.readFile(filePath);
    const extension = path.extname(filePath);
    res.writeHead(200, {
      "Content-Type": staticTypes[extension] || "application/octet-stream"
    });
    res.end(contents);
  } catch (error) {
    if (error.code === "ENOENT") {
      sendJson(res, 404, { error: "Not found" });
      return;
    }

    throw error;
  }
}

async function handleLogin(req, res) {
  let body;

  try {
    body = await readJsonBody(req);
  } catch (error) {
    sendJson(res, 400, { error: "Invalid JSON request body." });
    return;
  }

  const { username = "", password = "" } = body;

  if (!username || !password) {
    sendJson(res, 400, { error: "Username and password are required." });
    return;
  }

  const user = await authenticateUser(username, password);

  if (!user) {
    sendJson(res, 401, { error: "Invalid username or password." });
    return;
  }

  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, user.username);
  res.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
    "Set-Cookie": `session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`,
    "Cache-Control": "no-store"
  });
  res.end(JSON.stringify({ ok: true, redirectTo: "/frieren.html", authSource: user.source }));
}

function handleLogout(req, res) {
  const token = parseCookies(req).session;
  if (token) sessions.delete(token);

  res.writeHead(204, {
    "Set-Cookie": "session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
    "Cache-Control": "no-store"
  });
  res.end();
}

async function handleGetLdapConfig(req, res) {
  if (!requireUser(req, res)) return;

  const config = await loadLdapConfig();
  sendJson(res, 200, publicLdapConfig(config));
}

async function handleSaveLdapConfig(req, res) {
  if (!requireUser(req, res)) return;

  let body;

  try {
    body = await readJsonBody(req);
  } catch (error) {
    sendJson(res, 400, { error: "Invalid JSON request body." });
    return;
  }

  const previous = await loadLdapConfig();
  const next = normalizeLdapConfig(body, previous);
  await saveLdapConfig(next);
  sendJson(res, 200, { ok: true, config: publicLdapConfig(next) });
}

async function handleTestLdap(req, res) {
  if (!requireUser(req, res)) return;

  let body;

  try {
    body = await readJsonBody(req);
  } catch (error) {
    sendJson(res, 400, { error: "Invalid JSON request body." });
    return;
  }

  const { username = "", password = "" } = body;

  if (!username || !password) {
    sendJson(res, 400, { error: "LDAP test username and password are required." });
    return;
  }

  const config = await loadLdapConfig();

  if (!isLdapEnabled(config)) {
    sendJson(res, 400, { error: "LDAP is not enabled or is missing required settings." });
    return;
  }

  const ok = await authenticateWithLdap(username, password, config);
  sendJson(
    res,
    ok ? 200 : 401,
    ok ? { ok: true, message: "LDAP authentication succeeded." } : { error: "LDAP authentication failed." }
  );
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  try {
    if (req.method === "POST" && pathname === "/api/login") {
      await handleLogin(req, res);
      return;
    }

    if (req.method === "POST" && pathname === "/api/logout") {
      handleLogout(req, res);
      return;
    }

    if (req.method === "GET" && pathname === "/api/me") {
      const username = getCurrentUser(req);
      sendJson(res, username ? 200 : 401, username ? { username } : { error: "Not authenticated" });
      return;
    }

    if (req.method === "GET" && pathname === "/api/ldap-config") {
      await handleGetLdapConfig(req, res);
      return;
    }

    if (req.method === "PUT" && pathname === "/api/ldap-config") {
      await handleSaveLdapConfig(req, res);
      return;
    }

    if (req.method === "POST" && pathname === "/api/ldap-test") {
      await handleTestLdap(req, res);
      return;
    }

    if (req.method === "GET" && pathname === "/frieren.html" && !getCurrentUser(req)) {
      redirect(res, "/");
      return;
    }

    if (req.method === "GET") {
      await serveStatic(res, pathname);
      return;
    }

    sendJson(res, 405, { error: "Method not allowed" });
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { error: "Server error" });
  }
}

http.createServer(handleRequest).listen(PORT, () => {
  console.log(`Login app running at http://localhost:${PORT}`);
});
