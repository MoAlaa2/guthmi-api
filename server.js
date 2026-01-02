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
  res.json({
    status: 'ok',
    service: 'Guthmi API',
    timestamp: new Date().toISOString()
  });
});

/* =======================
   AUTH
======================= */
app.post('/api/login', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  res.json({
    token: 'dev-token-123',
    user: {
      id: 'usr_1',
      name: 'Mohamed Alaa',
      email,
      role: 'admin',
      permissions: ['*'],
      status: 'active',
      avatar: 'https://ui-avatars.com/api/?name=Admin'
    }
  });
});

/* =======================
   DASHBOARD / ANALYTICS
======================= */
app.get('/api/internal-notifications', (req, res) => {
  res.json([]);
});

app.get('/api/analytics/summary', (req, res) => {
  res.json({
    totalMessages: 0,
    delivered: 0,
    failed: 0,
    cost: 0
  });
});

/* =======================
   ORDERS
======================= */
app.get('/api/orders', (req, res) => {
  res.json([]);
});

/* =======================
   CONTACTS
======================= */
app.get('/api/contacts', (req, res) => {
  res.json([]);
});

/* =======================
   TEAM
======================= */
app.get('/api/team', (req, res) => {
  res.json([]);
});

/* =======================
   TEMPLATES
======================= */
app.get('/api/templates', (req, res) => {
  res.json([]);
});

/* =======================
   NOTIFICATIONS
======================= */
app.get('/api/notifications', (req, res) => {
  res.json([]);
});

app.post('/api/notifications', (req, res) => {
  res.json({
    id: Date.now().toString(),
    status: 'DRAFT'
  });
});

/* =======================
   404 HANDLER (آخر حاجة)
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
