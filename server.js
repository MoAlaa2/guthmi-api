import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import axios from "axios";

dotenv.config();

console.log("🚀 Guthmi API Loaded");

const app = express();
const PORT = process.env.PORT || 3000;

// ==============================
// Middleware
// ==============================
app.use(cors({
  origin: "*",
  credentials: true
}));
app.use(express.json());

// ==============================
// Meta / WhatsApp Config
// ==============================
const META_API_VERSION = "v22.0";
const BASE_URL = `https://graph.facebook.com/${META_API_VERSION}`;

const {
  META_ACCESS_TOKEN,
  WABA_ID,
  PHONE_NUMBER_ID
} = process.env;

const metaClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    Authorization: `Bearer ${META_ACCESS_TOKEN}`,
    "Content-Type": "application/json"
  }
});

// ==============================
// BASIC / HEALTH
// ==============================
app.get("/", (req, res) => {
  res.send("Guthmi API is running");
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    env: process.env.NODE_ENV || "dev",
    meta: {
      waba: !!WABA_ID,
      phone: !!PHONE_NUMBER_ID,
      token: !!META_ACCESS_TOKEN
    }
  });
});

// ==============================
// AUTH (LOGIN)
// ==============================
app.post("/api/login", (req, res) => {
  const { email } = req.body;

  res.json({
    token: "dev-token-123",
    user: {
      id: "usr_1",
      name: "Mohamed Alaa",
      email,
      role: "admin",
      permissions: ["*"]
    }
  });
});

// ==============================
// TEAM / USERS
// ==============================
app.get("/api/teams", (req, res) => {
  res.json([
    {
      id: "usr_1",
      name: "Mohamed Alaa",
      email: "admin@guthmi.com",
      role: "admin",
      permissions: ["*"]
    }
  ]);
});

// ==============================
// INTERNAL NOTIFICATIONS
// ==============================
app.get("/api/internal-notifications", (req, res) => {
  res.json([]);
});

// ==============================
// ANALYTICS
// ==============================
app.get("/api/analytics/summary", (req, res) => {
  res.json({
    totalMessages: 0,
    deliveredRate: 0,
    readRate: 0,
    failedRate: 0,
    totalCost: 0,
    costPerMessage: 0,
    avgReadTime: "0s",
    activeConversations: 0,
    peakHour: "-",
    trends: {
      messages: 0,
      cost: 0,
      read: 0
    }
  });
});

app.get("/api/analytics/timeline", (req, res) => res.json([]));
app.get("/api/analytics/cost", (req, res) => res.json([]));
app.get("/api/analytics/errors", (req, res) => res.json([]));
app.get("/api/analytics/agents", (req, res) => res.json([]));
app.get("/api/analytics/heatmap", (req, res) => res.json([]));

// ==============================
// SYSTEM / QUEUE
// ==============================
app.get("/api/system/queue-stats", (req, res) => {
  res.json({
    pending: 0,
    processing: 0,
    completed: 0,
    failed: 0,
    estimatedCompletion: "-",
    currentRate: 0
  });
});

// ==============================
// SETTINGS
// ==============================
app.get("/api/settings/protection", (req, res) => {
  res.json({
    emergencyStop: false,
    warmUpMode: false,
    maxDailyMessages: 1000,
    currentDailyCount: 0,
    baseDelayMs: 0,
    consecutiveFailures: 0,
    healthStatus: "HEALTHY"
  });
});

app.get("/api/settings/global", (req, res) => {
  res.json({
    inventory: {},
    invoicing: {},
    workingHours: {},
    sla: {}
  });
});

// ==============================
// TEMPLATES (META)
// ==============================
app.get("/api/templates", async (req, res) => {
  if (!WABA_ID) return res.json([]);

  try {
    const r = await metaClient.get(`/${WABA_ID}/message_templates`);
    res.json(r.data.data || []);
  } catch (e) {
    res.json([]);
  }
});

app.post("/api/templates", async (req, res) => {
  res.json({ status: "created", mock: true });
});

// ==============================
// MESSAGES (META)
// ==============================
app.post("/api/messages", async (req, res) => {
  if (!PHONE_NUMBER_ID) {
    return res.status(500).json({ error: "PHONE_NUMBER_ID missing" });
  }

  try {
    const r = await metaClient.post(`/${PHONE_NUMBER_ID}/messages`, {
      messaging_product: "whatsapp",
      ...req.body
    });
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: "Meta send failed" });
  }
});

// ==============================
// CONTACTS
// ==============================
app.get("/api/contacts", (req, res) => res.json([]));
app.get("/api/contact-lists", (req, res) => res.json([]));
app.get("/api/contact-tags", (req, res) => res.json([]));
app.post("/api/contacts", (req, res) => {
  res.json({ id: "c_" + Date.now(), ...req.body });
});

// ==============================
// CAMPAIGNS / NOTIFICATIONS
// ==============================
app.get("/api/campaigns", (req, res) => res.json([]));
app.post("/api/campaigns", (req, res) => {
  res.json({ id: "cmp_" + Date.now(), status: "DRAFT" });
});

// ==============================
// FALLBACK (NO 404 UI CRASH)
// ==============================
app.use("/api/*", (req, res) => {
  res.json([]);
});

// ==============================
// START SERVER
// ==============================
app.listen(PORT, () => {
  console.log(`✅ Guthmi API running on port ${PORT}`);
});
