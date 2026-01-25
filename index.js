const express = require("express");

const app = express();

// IMPORTANT: DigitalOcean will send requests to your app.
// We accept JSON and also raw text (some webhooks send non-JSON).
app.use(express.json({ limit: "1mb" }));
app.use(express.text({ type: "*/*", limit: "1mb" }));

// Health check (used by platforms / humans)
app.get("/", (req, res) => {
  res.status(200).send("OK");
});

// Main webhook endpoint
app.post("/webhook", (req, res) => {
  // Optional secret check (recommended once TradingView is wired)
  const expected = process.env.WEBHOOK_SECRET;
  if (expected) {
    const got = req.header("x-webhook-secret");
    if (!got || got !== expected) {
      return res.status(401).send("Unauthorized");
    }
  }

  // Log the payload (safe for now; later we’ll sanitize)
  const body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
  console.log("WEBHOOK_RECEIVED:", body);

  // Tell TradingView “success”
  res.status(200).json({ ok: true });
});

// DigitalOcean (and most platforms) provide PORT
const port = Number(process.env.PORT) || 8080;
app.listen(port, "0.0.0.0", () => {
  console.log(`Listening on port ${port}`);
});
