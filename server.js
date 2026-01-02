import express from "express";
import cors from "cors";
import "dotenv/config";

console.log("🚀 Guthmi API Loaded");

const app = express();

app.use(cors({
  origin: [
    "https://guthmi.site",
    "https://www.guthmi.site",
    "https://api.guthmi.site",
    /\.vercel\.app$/ // أي preview من Vercel
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  credentials: true
}));

app.use(express.json());

// =====================
// ROOT & HEALTH
// =====================
app.get("/", (req, res) => {
  res.send("ROOT OK");
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "Guthmi API" });
});

app.get("/api/version", (req, res) => {
  res.json({
    app: "Guthmi API",
    version: "1.0.0",
    status: "live"
  });
});

// =====================
// AUTH (TEMP LOGIN)
// =====================
app.post("/api/login", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  return res.json({
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

// =====================
// INTERNAL NOTIFICATIONS (MOCK)
// =====================
app.get("/api/internal-notifications", (req, res) => {
  res.json([]);
});

// =====================
// TEAM (MOCK)
// =====================
app.get("/api/team", (req, res) => {
  res.json([]);
});

// =====================
// FALLBACK FOR API
// =====================
app.use("/api", (req, res) => {
  res.status(404).json({
    message: "API route not implemented yet",
    path: req.originalUrl
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("✅ API running on port", PORT);
});
