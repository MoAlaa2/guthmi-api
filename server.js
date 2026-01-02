import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

/* =======================
   Middleware
======================= */
app.use(cors({
  origin: [
    'https://guthmi.site',
    'https://www.guthmi.site',
    'http://localhost:5173'
  ],
  credentials: true
}));

app.use(express.json());

/* =======================
   Base Routes
======================= */
app.get('/', (req, res) => {
  res.send('Guthmi API is running');
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

/* =======================
   API ROUTES (NO WILDCARDS)
======================= */

// AUTH (temporary fake login)
app.post('/api/login', (req, res) => {
  const { email } = req.body;

  res.json({
    token: 'dev-token-123',
    user: {
      id: 'usr_1',
      name: 'Mohamed Alaa',
      email,
      role: 'admin',
      permissions: ['*']
    }
  });
});

// Internal Notifications
app.get('/api/internal-notifications', (req, res) => {
  res.json([]);
});

// Orders
app.get('/api/orders', (req, res) => {
  res.json([]);
});

// Contacts
app.get('/api/contacts', (req, res) => {
  res.json([]);
});

// Teams
app.get('/api/team', (req, res) => {
  res.json([]);
});

// Templates
app.get('/api/templates', (req, res) => {
  res.json([]);
});

/* =======================
   404 HANDLER
======================= */
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl
  });
});

/* =======================
   START SERVER
======================= */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Guthmi API running on port ${PORT}`);
});
