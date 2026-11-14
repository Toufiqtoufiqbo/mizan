"use strict";

/**
 * A standalone store API - an independent Express validation target for Mizan.
 *
 * This application knows nothing about Mizan. It has:
 *
 * * its own authentication - opaque random tokens in its own database;
 * * its own SQLite database, through Node's built-in `node:sqlite`;
 * * its own OpenAPI document (`openapi.json` next to this file);
 * * its own rules about who may touch which order.
 *
 * The only thing Mizan uses is ordinary HTTP, plus the database file for
 * attribution - the same way it would work against a real application.
 *
 * The weaknesses are independent, so an experiment changes exactly one thing:
 *
 *   --vulnerability read   only the read check is removed. Writing somebody
 *                          else's order is still refused.
 *   --vulnerability write  only the write check is removed. Reading somebody
 *                          else's order is still refused.
 *   --vulnerability both   both checks are removed.
 *
 * The listing of orders is **always** scoped to the caller in every variant.
 *
 * Usage:
 *   node server.js --db store.sqlite --port 8000 --vulnerability clean
 */

const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const express = require("express");

/** The independent weaknesses a variant can carry. */
const VARIANTS = ["clean", "read", "write", "both"];

/** Test credentials, injected per run through the environment. */
const DEFAULT_CREDENTIALS = {
  alice: "MIZAN_TEST_ALICE",
  bob: "MIZAN_TEST_BOB",
  root: "MIZAN_TEST_ROOT",
};

/** Orders owned by root, so a cross-user read and write are both possible. */
const SEED_ORDERS = [
  { id: "ord-seed-1", owner_id: "root", sku: "SKU-SEED-1", quantity: 2, status: "created" },
  { id: "ord-seed-2", owner_id: "root", sku: "SKU-SEED-2", quantity: 1, status: "created" },
];

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  sku TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL
);
`;

/** The seconds since the epoch, which is what `created_at` stores. */
function now() {
  return Date.now() / 1000;
}

/** The wire shape of an order. */
function orderJson(row) {
  return {
    id: row.id,
    owner_id: row.owner_id,
    sku: row.sku,
    quantity: row.quantity,
    status: row.status,
    created_at: row.created_at,
  };
}

/**
 * Build the store API.
 *
 * `settings.vulnerability` names the weakness to inject. Anything outside
 * `VARIANTS` is an error - a variant that does not exist must not be mistaken
 * for the clean one.
 */
function createApp(database, settings) {
  if (!VARIANTS.includes(settings.vulnerability)) {
    throw new Error(`unknown variant: ${settings.vulnerability}; expected one of ${VARIANTS.join(", ")}`);
  }

  const db = new DatabaseSync(database);
  db.exec(SCHEMA);

  const insertUser = db.prepare("INSERT OR IGNORE INTO users (id, password, role) VALUES (?, ?, ?)");
  for (const [user, password] of Object.entries(settings.credentials)) {
    insertUser.run(user, password, user === "root" ? "admin" : "user");
  }
  const insertOrder = db.prepare(
    "INSERT OR IGNORE INTO orders (id, owner_id, sku, quantity, status, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  );
  for (const order of SEED_ORDERS) {
    insertOrder.run(order.id, order.owner_id, order.sku, order.quantity, order.status, now());
  }

  const app = express();
  app.use(express.json({ strict: true }));

  /** The identity behind the bearer token, or null. */
  function currentUser(req) {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) {
      return null;
    }
    const token = header.slice("Bearer ".length).trim();
    const row = db.prepare("SELECT user_id FROM tokens WHERE token = ?").get(token);
    return row ? row.user_id : null;
  }

  function isAdmin(userId) {
    const row = db.prepare("SELECT role FROM users WHERE id = ?").get(userId);
    return Boolean(row) && row.role === "admin";
  }

  function mayRead(order, userId) {
    if (settings.vulnerability === "read" || settings.vulnerability === "both") {
      return true;
    }
    return order.owner_id === userId || isAdmin(userId);
  }

  function mayWrite(order, userId) {
    if (settings.vulnerability === "write" || settings.vulnerability === "both") {
      return true;
    }
    return order.owner_id === userId || isAdmin(userId);
  }

  function fetchOrder(orderId) {
    return db.prepare("SELECT * FROM orders WHERE id = ?").get(orderId);
  }

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  // -- authentication --------------------------------------------------- //

  app.post("/login", (req, res) => {
    const body = req.body || {};
    const { username, password } = body;
    if (typeof username !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "username and password are required" });
    }
    const row = db.prepare("SELECT id FROM users WHERE id = ? AND password = ?").get(username, password);
    if (!row) {
      return res.status(401).json({ error: "invalid credentials" });
    }
    const token = crypto.randomBytes(32).toString("base64url");
    db.prepare("INSERT INTO tokens (token, user_id, created_at) VALUES (?, ?, ?)").run(
      token,
      username,
      now()
    );
    return res.json({ token, user_id: username });
  });

  app.get("/me", (req, res) => {
    const userId = currentUser(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthenticated" });
    }
    const row = db.prepare("SELECT id, role FROM users WHERE id = ?").get(userId);
    return res.json({ id: row.id, role: row.role, owner_id: row.id });
  });

  // -- orders ------------------------------------------------------------ //

  app.post("/orders", (req, res) => {
    const userId = currentUser(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthenticated" });
    }
    const body = req.body || {};
    const { sku, quantity } = body;
    if (typeof sku !== "string" || sku.length === 0) {
      return res.status(400).json({ error: "sku is required" });
    }
    if (!Number.isInteger(quantity) || quantity < 1) {
      return res.status(400).json({ error: "quantity must be a positive integer" });
    }
    const id = `ord-${crypto.randomBytes(6).toString("hex")}`;
    db.prepare(
      "INSERT INTO orders (id, owner_id, sku, quantity, status, created_at) VALUES (?, ?, ?, ?, 'created', ?)"
    ).run(id, userId, sku, quantity, now());
    return res.status(201).json(orderJson(fetchOrder(id)));
  });

  app.get("/orders", (req, res) => {
    const userId = currentUser(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthenticated" });
    }
    // The listing is always scoped to the caller, in every variant.
    const rows = db.prepare("SELECT * FROM orders WHERE owner_id = ? ORDER BY created_at").all(userId);
    return res.json({ orders: rows.map(orderJson) });
  });

  app.get("/orders/:order_id", (req, res) => {
    const userId = currentUser(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthenticated" });
    }
    const row = fetchOrder(req.params.order_id);
    if (!row) {
      return res.status(404).json({ error: "order not found" });
    }
    if (!mayRead(row, userId)) {
      return res.status(403).json({ error: "forbidden" });
    }
    return res.json(orderJson(row));
  });

  app.put("/orders/:order_id", (req, res) => {
    const userId = currentUser(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthenticated" });
    }
    const row = fetchOrder(req.params.order_id);
    if (!row) {
      return res.status(404).json({ error: "order not found" });
    }
    if (!mayWrite(row, userId)) {
      return res.status(403).json({ error: "forbidden" });
    }
    const body = req.body || {};
    if (typeof body.status !== "string" || body.status.length === 0) {
      return res.status(400).json({ error: "status is required" });
    }
    db.prepare("UPDATE orders SET status = ? WHERE id = ?").run(body.status, req.params.order_id);
    return res.json(orderJson(fetchOrder(req.params.order_id)));
  });

  return app;
}

/** Read the command line. */
function parseArgs(argv) {
  const result = { db: "store.sqlite", port: 0, vulnerability: "clean" };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--db") {
      result.db = argv[(index += 1)];
    } else if (argument === "--port") {
      result.port = Number.parseInt(argv[(index += 1)], 10);
    } else if (argument === "--vulnerability") {
      result.vulnerability = argv[(index += 1)];
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  return result;
}

/** The entry point. */
function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!VARIANTS.includes(args.vulnerability)) {
    throw new Error(`unknown variant: ${args.vulnerability}; expected one of ${VARIANTS.join(", ")}`);
  }
  const credentials = {};
  for (const [user, env] of Object.entries(DEFAULT_CREDENTIALS)) {
    credentials[user] = process.env[env] || `${user}-secret`;
  }
  const app = createApp(args.db, { vulnerability: args.vulnerability, credentials });
  const server = app.listen(args.port, "127.0.0.1", () => {
    process.stdout.write(
      `store api listening on http://127.0.0.1:${args.port} (variant ${args.vulnerability})\n`
    );
  });
  const shutdown = () => {
    server.close(() => process.exit(0));
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

module.exports = { createApp, VARIANTS, orderJson };

if (require.main === module) {
  main();
}
