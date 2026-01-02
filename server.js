import express from "express";
import cors from "cors";
import "dotenv/config";

const app = express();

// ======================
// CORS (Railway Safe)
// ======================
app.use(cors({
  origin: [
    "https://guthmi.site",
    "https://www.guthmi.site",
    "https://guthmi-wa.vercel.app",
    /\.vercel\.app$/
  ],
  credentials: true
}));

app.use(express.json());

// ======================
// HEALTH
// ======================
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "Guthmi API" });
});

// ======================
// AUTH (TEMP DEV LOGIN)
// ======================
app.post("/api/login", (req, res) => {
  const { email } = req.body;

  // 🔥 Dev user مؤقت
  res.json({
    token: "dev-token-123",
    user: {
      id: "usr_1",
      name: "Mohamed Alaa",
      email,
      role: "admin",
      permissions: ["*"],
      status: "active"
    }
  });
});

// ======================
// TEAM
// ======================
app.get("/api/team", (req, res) => {
  res.json([]);
});

// ======================
// FALLBACK (Express 5 Safe)
// ======================
app.use("/api", (req, res) => {
  res.status(404).json({ error: "API route not found" });
});

// ======================
// QUICK REPLIES
// ======================
app.get("/api/quick-replies", (req, res) => {
  res.json([]);
});

// ======================
// TAGS
// ======================
app.get("/api/tags", (req, res) => {
  res.json([]);
});

// ======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Guthmi API running on port", PORT);
});
