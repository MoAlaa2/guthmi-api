import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';

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

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

/* =======================
   META CONFIG (optional)
======================= */
const META_API_VERSION = 'v22.0';
const BASE_URL = `https://graph.facebook.com/${META_API_VERSION}`;
const { META_ACCESS_TOKEN, WABA_ID, PHONE_NUMBER_ID } = process.env;

const metaClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    Authorization: `Bearer ${META_ACCESS_TOKEN}`,
    'Content-Type': 'application/json'
  }
});

/* =======================
   MOCK DATABASE (Railway-safe)
======================= */
const users = [
  {
    id: 'usr_1',
    name: 'Mohamed Alaa',
    email: 'admin@guthmi.com',
    role: 'admin',
    permissions: ['*'],
    status: 'active',
    avatar: 'https://ui-avatars.com/api/?name=Admin'
  }
];

const conversations = [
  {
    id: 'conv_1',
    contactName: 'Test Customer',
    contactNumber: '+966500000000',
    lastMessage: 'Hello',
    lastMessageTimestamp: new Date().toISOString(),
    unreadCount: 1,
    status: 'open',
    avatar: 'https://ui-avatars.com/api/?name=Customer'
  }
];

const messages = {
  conv_1: [
    {
      id: 'm1',
      conversationId: 'conv_1',
      content: 'Hello',
      type: 'text',
      direction: 'inbound',
      status: 'read',
      timestamp: new Date().toISOString()
    }
  ]
};

const internalNotifications = [
  {
    id: 'n1',
    title: 'System Ready',
    description: 'Railway backend is live',
    type: 'SYSTEM',
    priority: 'NORMAL',
    read: false,
    timestamp: new Date().toISOString()
  }
];

/* =======================
   BASE
======================= */
app.get('/', (req, res) => {
  res.send('Guthmi API is running');
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

/* =======================
   AUTH
======================= */
app.post('/api/login', (req, res) => {
  const { email } = req.body;
  const user = users.find(u => u.email === email) || users[0];

  res.json({
    token: 'dev-token-123',
    user
  });
});

/* =======================
   TEAM
======================= */
app.get('/api/team', (req, res) => {
  res.json(users);
});

/* =======================
   INTERNAL NOTIFICATIONS
======================= */
app.get('/api/internal-notifications', (req, res) => {
  res.json(internalNotifications);
});

/* =======================
   INBOX
======================= */
app.get('/api/conversations', (req, res) => {
  res.json(conversations);
});

app.get('/api/conversations/:id/messages', (req, res) => {
  res.json(messages[req.params.id] || []);
});

app.post('/api/conversations/:id/messages', async (req, res) => {
  const { content } = req.body;

  const msg = {
    id: 'm_' + Date.now(),
    conversationId: req.params.id,
    content,
    type: 'text',
    direction: 'outbound',
    status: 'sent',
    timestamp: new Date().toISOString()
  };

  messages[req.params.id] = messages[req.params.id] || [];
  messages[req.params.id].push(msg);

  // Optional Meta send
  if (PHONE_NUMBER_ID && META_ACCESS_TOKEN) {
    metaClient.post(`/${PHONE_NUMBER_ID}/messages`, {
      messaging_product: 'whatsapp',
      to: conversations[0].contactNumber,
      type: 'text',
      text: { body: content }
    }).catch(() => {});
  }

  res.json(msg);
});

/* =======================
   ORDERS
======================= */
app.get('/api/orders', (req, res) => {
  res.json([]);
});

/* =======================
   ANALYTICS
======================= */
app.get('/api/analytics/summary', (req, res) => {
  res.json({
    totalMessages: 12,
    deliveredRate: 98,
    readRate: 87,
    failedRate: 2,
    totalCost: 1.4
  });
});

/* =======================
   TEMPLATES
======================= */
app.get('/api/templates', async (req, res) => {
  if (WABA_ID && META_ACCESS_TOKEN) {
    try {
      const r = await metaClient.get(`/${WABA_ID}/message_templates`);
      return res.json(r.data.data || []);
    } catch (e) {}
  }
  res.json([]);
});

/* =======================
   404
======================= */
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl
  });
});

/* =======================
   START
======================= */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Guthmi API running on port ${PORT}`);
});
