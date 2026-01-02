import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

/* ======================
   MIDDLEWARE
====================== */
app.use(cors());
app.use(express.json());

/* ======================
   META CONFIG
====================== */
const META_API_VERSION = 'v22.0';
const BASE_URL = `https://graph.facebook.com/${META_API_VERSION}`;
const { META_ACCESS_TOKEN, WABA_ID, PHONE_NUMBER_ID } = process.env;

const metaClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    Authorization: `Bearer ${META_ACCESS_TOKEN || ''}`,
    'Content-Type': 'application/json',
  },
});

/* ======================
   CORE
====================== */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Guthmi API',
    timestamp: new Date().toISOString(),
    meta: {
      token: !!META_ACCESS_TOKEN,
      waba: !!WABA_ID,
      phone: !!PHONE_NUMBER_ID,
    },
  });
});

app.get('/api/version', (req, res) => {
  res.json({ version: '1.0.0', env: process.env.NODE_ENV || 'prod' });
});

/* ======================
   AUTH
====================== */
app.post('/api/login', (req, res) => {
  res.json({
    token: 'dev-token-123',
    user: {
      id: 'usr_1',
      name: 'Mohamed Alaa',
      email: req.body.email,
      role: 'admin',
      permissions: ['*'],
    },
  });
});

app.get('/api/me', (req, res) => {
  res.json({
    id: 'usr_1',
    name: 'Mohamed Alaa',
    role: 'admin',
    permissions: ['*'],
  });
});

/* ======================
   TEAM
====================== */
app.get('/api/team', (req, res) => res.json([]));
app.post('/api/team', (req, res) => res.json(req.body));
app.put('/api/team/:id', (req, res) => res.json(req.body));
app.delete('/api/team/:id', (req, res) => res.json({ success: true }));

/* ======================
   TEMPLATES (META)
====================== */
app.get('/api/templates', async (req, res) => {
  if (!WABA_ID) return res.json([]);

  try {
    const r = await metaClient.get(`/${WABA_ID}/message_templates`, {
      params: { limit: 100 },
    });
    res.json(r.data?.data || []);
  } catch {
    res.json([]);
  }
});

app.post('/api/templates', async (req, res) => {
  if (!WABA_ID) return res.status(500).json({ error: 'WABA_ID missing' });

  try {
    const r = await metaClient.post(`/${WABA_ID}/message_templates`, req.body);
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: 'Meta template error' });
  }
});

/* ======================
   MESSAGES (META)
====================== */
app.post('/api/messages', async (req, res) => {
  if (!PHONE_NUMBER_ID) return res.status(500).json({ error: 'PHONE_NUMBER_ID missing' });

  try {
    const r = await metaClient.post(`/${PHONE_NUMBER_ID}/messages`, {
      messaging_product: 'whatsapp',
      ...req.body,
    });
    res.json(r.data);
  } catch {
    res.status(500).json({ error: 'Send message failed' });
  }
});

/* ======================
   INBOX
====================== */
app.get('/api/conversations', (req, res) => res.json([]));
app.get('/api/conversations/:id/messages', (req, res) => res.json([]));
app.post('/api/conversations/:id/messages', (req, res) => res.json({}));

/* ======================
   ORDERS
====================== */
app.get('/api/orders', (req, res) => res.json([]));
app.post('/api/orders', (req, res) => res.json(req.body));
app.put('/api/orders/:id', (req, res) => res.json(req.body));
app.put('/api/orders/:id/status', (req, res) => res.json(req.body));
app.post('/api/orders/:id/invoice', (req, res) => res.json({ url: '' }));

/* ======================
   CONTACTS
====================== */
app.get('/api/contacts', (req, res) => res.json([]));
app.post('/api/contacts', (req, res) => res.json(req.body));
app.get('/api/contacts/count', (req, res) => res.json({ count: 0 }));

app.get('/api/contact-lists', (req, res) => res.json([]));
app.get('/api/contact-tags', (req, res) => res.json([]));
app.post('/api/contacts/import', (req, res) =>
  res.json({ id: 'job_' + Date.now(), status: 'processing' })
);
app.get('/api/contacts/import-history', (req, res) => res.json([]));

/* ======================
   NOTIFICATIONS
====================== */
app.get('/api/internal-notifications', (req, res) => res.json([]));
app.post('/api/internal-notifications', (req, res) => res.json({}));
app.post('/api/internal-notifications/:id/read', (req, res) => res.json({}));

app.get('/api/notifications', (req, res) => res.json([]));
app.post('/api/notifications', (req, res) => res.json({ id: Date.now(), status: 'DRAFT' }));
app.post('/api/notifications/:id/send', (req, res) =>
  res.json({ status: 'RUNNING', startedAt: new Date().toISOString() })
);

/* ======================
   ANALYTICS
====================== */
app.get('/api/analytics/summary', (req, res) => res.json({}));
app.get('/api/analytics/timeline', (req, res) => res.json([]));
app.get('/api/analytics/cost', (req, res) => res.json([]));
app.get('/api/analytics/errors', (req, res) => res.json([]));
app.get('/api/analytics/agents', (req, res) => res.json([]));
app.get('/api/analytics/heatmap', (req, res) => res.json([]));

/* ======================
   SETTINGS
====================== */
app.get('/api/settings/global', (req, res) => res.json({}));
app.put('/api/settings/global', (req, res) => res.json(req.body));

app.get('/api/settings/protection', (req, res) => res.json({}));
app.put('/api/settings/protection', (req, res) => res.json(req.body));

app.get('/api/system/queue-stats', (req, res) =>
  res.json({ pending: 0, processing: 0, completed: 0 })
);

/* ======================
   FALLBACK (NO 404)
====================== */
app.use('/api', (req, res) => res.json([]));

/* ======================
   START
====================== */
app.listen(PORT, () => {
  console.log(`🚀 Guthmi API running on port ${PORT}`);
});
