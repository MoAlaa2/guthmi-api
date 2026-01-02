import express from "express";
import cors from "cors";

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("API running on port", PORT);
});
