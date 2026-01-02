import express from "express";
import cors from "cors";
import "dotenv/config";

console.log(" ^=^z^` SERVER FILE LOADED");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("ROOT OK");
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "Guthmi API" });
});

app.get("/api/version", (req, res) => {
  res.json({
    app: "Guthmi API",
    version: "1.0.0",
    status: "live"
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("API running on port", PORT);
});
