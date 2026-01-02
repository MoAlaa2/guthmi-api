import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';

// Fix for missing node types in some environments
//declare const require: any;
//declare const module: any;

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// Request Logging Middleware (Crucial for debugging)
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// --- META API CONFIGURATION ---
const META_API_VERSION = 'v22.0';
const BASE_URL = `https://graph.facebook.com/${META_API_VERSION}`;
const { META_ACCESS_TOKEN, WABA_ID, PHONE_NUMBER_ID } = process.env;

const metaClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Authorization': `Bearer ${META_ACCESS_TOKEN}`,
    'Content-Type': 'application/json',
  },
});

// --- IN-MEMORY DATABASE (SINGLE SOURCE OF TRUTH) ---
// This creates a persistent state while the server is running.

const DB = {
  users: [
    { 
      id: 'u1', 
      name: 'Admin User', 
      email: 'admin@guthmi.com', 
      role: 'admin', 
      permissions: ['*'], // Wildcard for full access
      status: 'active', 
      avatar: 'https://ui-avatars.com/api/?name=Admin+User&background=0D8ABC&color=fff',
      agentMode: 'senior'
    },
    { 
      id: 'u2', 
      name: 'Support Agent', 
      email: 'agent@guthmi.com', 
      role: 'agent', 
      permissions: ['view_inbox', 'manage_contacts'], 
      status: 'active', 
      avatar: 'https://ui-avatars.com/api/?name=Support+Agent&background=16a34a&color=fff',
      agentMode: 'standard'
    }
  ],
  contacts: [
    { 
      id: 'c1', 
      firstName: 'Alice', 
      lastName: 'Doe', 
      phone: '+1234567890', 
      email: 'alice@example.com', 
      status: 'SUBSCRIBED', 
      tags: ['t1'], 
      lists: ['l1'], 
      customAttributes: { city: 'Dubai' }, 
      createdAt: new Date().toISOString(), 
      lastModified: new Date().toISOString(),
      avatar: 'https://ui-avatars.com/api/?name=Alice+Doe'
    },
    { 
      id: 'c2', 
      firstName: 'Bob', 
      lastName: 'Smith', 
      phone: '+97150000000', 
      email: 'bob@example.com', 
      status: 'SUBSCRIBED', 
      tags: [], 
      lists: [], 
      customAttributes: {}, 
      createdAt: new Date(Date.now() - 86400000).toISOString(), 
      lastModified: new Date().toISOString(),
      avatar: 'https://ui-avatars.com/api/?name=Bob+Smith'
    }
  ],
  conversations: [
    { 
      id: 'conv_1', 
      contactName: 'Alice Doe', 
      contactNumber: '+1234567890', 
      lastMessage: 'I need help with my order', 
      lastMessageTimestamp: new Date().toISOString(), 
      lastCustomerMessageTimestamp: new Date().toISOString(),
      unreadCount: 1, 
      status: 'open', 
      assignedAgentId: null, 
      isLocked: false, 
      lockedByAgentId: null,
      systemTags: [{id: 'st1', key: 'sentiment', value: 'Neutral', color: '#64748b'}],
      tags: ['t1'],
      avatar: 'https://ui-avatars.com/api/?name=Alice+Doe'
    },
    { 
      id: 'conv_2', 
      contactName: 'Bob Smith', 
      contactNumber: '+97150000000', 
      lastMessage: 'Thanks for the update', 
      lastMessageTimestamp: new Date(Date.now() - 3600000).toISOString(), 
      lastCustomerMessageTimestamp: new Date(Date.now() - 3600000).toISOString(),
      unreadCount: 0, 
      status: 'open', 
      assignedAgentId: 'u2', 
      isLocked: true, 
      lockedByAgentId: 'u2',
      systemTags: [],
      tags: [],
      avatar: 'https://ui-avatars.com/api/?name=Bob+Smith'
    }
  ],
  messages: {
    'conv_1': [
      { id: 'm1', conversationId: 'conv_1', type: 'text', content: 'Hi there!', timestamp: new Date(Date.now() - 100000).toISOString(), direction: 'inbound', status: 'read' },
      { id: 'm2', conversationId: 'conv_1', type: 'text', content: 'I need help with my order', timestamp: new Date().toISOString(), direction: 'inbound', status: 'delivered' }
    ],
    'conv_2': [
      { id: 'm3', conversationId: 'conv_2', type: 'text', content: 'Your order is confirmed.', timestamp: new Date(Date.now() - 7200000).toISOString(), direction: 'outbound', status: 'read' },
      { id: 'm4', conversationId: 'conv_2', type: 'text', content: 'Thanks for the update', timestamp: new Date(Date.now() - 3600000).toISOString(), direction: 'inbound', status: 'read' }
    ]
 },
  orders: [],
  campaigns: [],
  templates: [], 
  internalNotifications: [
    {
      id: 'notif_1',
      title: 'System Online',
      description: 'The backend services are connected successfully.',
      type: 'SYSTEM',
      priority: 'NORMAL',
      timestamp: new Date().toISOString(),
      read: false
    }
  ],
  tags: [
    { id: 't1', name: 'VIP', color: '#FF0000', createdAt: new Date().toISOString() },
    { id: 't2', name: 'New Customer', color: '#10B981', createdAt: new Date().toISOString() }
  ],
  lists: [
    { id: 'l1', name: 'Newsletter', count: 1, isDefault: true, createdAt: new Date().toISOString() }
  ],
  products: [
    { id: 'p1', name: 'Premium Service', sku: 'SRV-001', price: 500, stock: 100, manageStock: false, image: '' },
    { id: 'p2', name: 'Physical Good', sku: 'PHY-002', price: 150, stock: 20, manageStock: true, image: '' }
  ],
  queue: { pending: 0, processing: 0, completed: 124, failed: 2, currentRate: 1.5, estimatedCompletion: '0s' },
  protection: { emergencyStop: false, warmUpMode: false, maxDailyMessages: 1000, currentDailyCount: 45, baseDelayMs: 100, consecutiveFailures: 0, healthStatus: 'HEALTHY' },
  globalSettings: {
    inventory: { reserveOnApproval: false, lowStockThreshold: 5 },
    invoicing: { autoGenerate: false, companyName: 'Guthmi Enterprise', taxId: 'TRN-12345' },
    workingHours: { enabled: false, timezone: 'Asia/Dubai', schedule: {}, holidays: [], offHoursMessage: 'We are currently closed.' },
    sla: { firstResponseMinutes: 60, resolutionHours: 24 }
  }
};

// --- ROUTES ---

// 1. AUTH & TEAM
app.post('/api/auth/login', (req, res) => {
  const { email } = req.body;
  // Simple auth: find user by email or default to admin if dev mode
  const user = DB.users.find(u => u.email === email) || DB.users[0];
  
  if (user) {
    res.json({
      ...user,
      token: 'mock_jwt_token_' + Date.now()
    });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/api/team', (req, res) => {
  res.json(DB.users);
});

app.post('/api/team', (req, res) => {
  const newUser = { 
    id: 'u_' + Date.now(), 
    status: 'active',
    avatar: `https://ui-avatars.com/api/?name=${req.body.name || 'User'}`,
    ...req.body 
  };
  DB.users.push(newUser);
  res.json(newUser);
});

app.put('/api/team/:id', (req, res) => {
  const idx = DB.users.findIndex(u => u.id === req.params.id);
  if (idx > -1) {
    DB.users[idx] = { ...DB.users[idx], ...req.body };
    res.json(DB.users[idx]);
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

app.delete('/api/team/:id', (req, res) => {
  DB.users = DB.users.filter(u => u.id !== req.params.id);
  res.json({ success: true });
});

// 2. CONTACTS & LISTS
app.get('/api/contacts', (req, res) => {
  res.json(DB.contacts);
});

app.get('/api/contacts/count', (req, res) => {
  res.json({ count: DB.contacts.length });
});

app.post('/api/contacts', (req, res) => {
  const contact = { 
    id: 'c_' + Date.now(), 
    createdAt: new Date().toISOString(), 
    lastModified: new Date().toISOString(),
    avatar: `https://ui-avatars.com/api/?name=${req.body.firstName}`,
    lists: [],
    tags: [],
    customAttributes: {},
    ...req.body 
  };
  DB.contacts.push(contact);

  // Auto-create conversation stub
  const existingConv = DB.conversations.find(c => c.contactNumber === contact.phone);
  if (!existingConv) {
    const newConv = {
      id: 'conv_' + contact.id,
      contactName: `${contact.firstName} ${contact.lastName || ''}`,
      contactNumber: contact.phone,
      lastMessage: '',
      lastMessageTimestamp: new Date().toISOString(),
      lastCustomerMessageTimestamp: new Date().toISOString(),
      unreadCount: 0,
      status: 'open',
      avatar: contact.avatar,
      isLocked: false,
      lockedByAgentId: null,
      assignedAgentId: null,
      tags: [],
      systemTags: []
    };
    DB.conversations.unshift(newConv); // Add to top
    DB.messages[newConv.id] = [];
  }

  res.json(contact);
});

app.put('/api/contacts/:id', (req, res) => {
  const idx = DB.contacts.findIndex(c => c.id === req.params.id);
  if (idx > -1) {
    DB.contacts[idx] = { ...DB.contacts[idx], ...req.body, lastModified: new Date().toISOString() };
    res.json(DB.contacts[idx]);
  } else {
    res.status(404).json({ error: 'Contact not found' });
  }
});

app.delete('/api/contacts/:id', (req, res) => {
  DB.contacts = DB.contacts.filter(c => c.id !== req.params.id);
  res.json({ success: true });
});

app.get('/api/contact-lists', (req, res) => res.json(DB.lists));
app.post('/api/contact-lists', (req, res) => {
  const list = { id: 'l_' + Date.now(), count: 0, createdAt: new Date().toISOString(), ...req.body };
  DB.lists.push(list);
  res.json(list);
});

app.get('/api/contact-tags', (req, res) => res.json(DB.tags));
app.post('/api/contact-tags', (req, res) => {
  const tag = { id: 't_' + Date.now(), count: 0, ...req.body };
  DB.tags.push(tag);
  res.json(tag);
});

// 3. INBOX & MESSAGING
app.get('/api/conversations', (req, res) => {
  // Sort by last message desc
  const sorted = [...DB.conversations].sort((a, b) => 
    new Date(b.lastMessageTimestamp).getTime() - new Date(a.lastMessageTimestamp).getTime()
  );
  res.json(sorted);
});

app.put('/api/conversations/:id', (req, res) => {
  const idx = DB.conversations.findIndex(c => c.id === req.params.id);
  if (idx > -1) {
    DB.conversations[idx] = { ...DB.conversations[idx], ...req.body };
    res.json(DB.conversations[idx]);
  } else {
    res.status(404).send();
  }
});

app.get('/api/conversations/:id/messages', (req, res) => {
  res.json(DB.messages[req.params.id] || []);
});

app.post('/api/conversations/:id/messages', (req, res) => {
  const convId = req.params.id;
  const { content, type } = req.body;
  const msg = {
    id: 'm_' + Date.now(),
    conversationId: convId,
    content,
    type,
    direction: 'outbound',
    status: 'sent', // Initially sent
    timestamp: new Date().toISOString(),
    senderName: 'You' // Or current user name
  };

  if (!DB.messages[convId]) DB.messages[convId] = [];
  DB.messages[convId].push(msg);

  // Update conversation metadata
  const conv = DB.conversations.find(c => c.id === convId);
  if (conv) {
    if (type !== 'note') {
        conv.lastMessage = type === 'text' ? content : `Sent a ${type}`;
        conv.lastMessageTimestamp = msg.timestamp;
    }
  }

  // Simulate delivery/read status updates after delay
  setTimeout(() => { msg.status = 'delivered'; }, 1500);
  setTimeout(() => { msg.status = 'read'; }, 3000);

  res.json(msg);
});

app.post('/api/conversations/:id/lock', (req, res) => {
  const conv = DB.conversations.find(c => c.id === req.params.id);
  if (conv) {
    conv.isLocked = true;
    conv.lockedByAgentId = req.body.userId;
    conv.assignedAgentId = req.body.userId;
    res.json({ success: true });
  } else res.status(404).send();
});

app.post('/api/conversations/:id/unlock', (req, res) => {
  const conv = DB.conversations.find(c => c.id === req.params.id);
  if (conv) {
    conv.isLocked = false;
    conv.lockedByAgentId = null;
    res.json({ success: true });
  } else res.status(404).send();
});

app.post('/api/conversations/bulk-assign', (req, res) => {
  const { conversationIds, agentId } = req.body;
  DB.conversations.forEach(c => {
    if (conversationIds.includes(c.id)) {
      c.assignedAgentId = agentId;
      if (agentId) {
          c.isLocked = true;
          c.lockedByAgentId = agentId;
      } else {
          c.isLocked = false;
          c.lockedByAgentId = null;
      }
    }
  });
  res.json({ success: true });
});

// 4. CAMPAIGNS
app.get('/api/campaigns', (req, res) => {
  res.json(DB.campaigns);
});

app.post('/api/campaigns', (req, res) => {
  const camp = { 
    id: 'camp_' + Date.now(), 
    ...req.body, 
    createdAt: new Date().toISOString(),
    stats: { total: req.body.stats?.total || 0, sent: 0, delivered: 0, read: 0, failed: 0 }
  };
  DB.campaigns.push(camp);
  res.json(camp);
});

app.put('/api/campaigns/:id', (req, res) => {
  const idx = DB.campaigns.findIndex(c => c.id === req.params.id);
  if (idx > -1) {
    DB.campaigns[idx] = { ...DB.campaigns[idx], ...req.body };
    res.json(DB.campaigns[idx]);
  } else res.status(404).send();
});

app.post('/api/campaigns/:id/toggle', (req, res) => {
  const camp = DB.campaigns.find(c => c.id === req.params.id);
  if (camp) {
    if (camp.status === 'RUNNING') camp.status = 'PAUSED';
    else if (['PAUSED', 'DRAFT'].includes(camp.status)) camp.status = 'RUNNING';
    res.json(camp);
  } else res.status(404).send();
});

app.delete('/api/campaigns/:id', (req, res) => {
  DB.campaigns = DB.campaigns.filter(c => c.id !== req.params.id);
  res.json({ success: true });
});

// 5. ORDERS
app.get('/api/orders', (req, res) => {
  res.json(DB.orders);
});

app.post('/api/orders', (req, res) => {
  const order = {
    id: 'ord_' + Date.now(),
    orderNumber: 'ORD-' + (1000 + DB.orders.length),
    createdAt: new Date().toISOString(),
    history: [{ action: 'created', timestamp: new Date().toISOString(), userName: 'System' }],
    approvalStatus: req.body.requiresApproval ? 'pending_approval' : 'approved',
    status: 'pending-payment',
    ...req.body
  };
  
  // Calculations
  const subtotal = order.items.reduce(
  (acc, i) => acc + (i.price * i.quantity),
  0
);
  order.subtotal = subtotal;
  order.tax = subtotal * 0.15;
  order.total = subtotal + order.tax - (order.discount || 0);

  if (order.approvalStatus === 'approved') {
      order.paymentLink = `https://pay.guthmi.com/${order.id}`;
  }

  DB.orders.unshift(order);
  res.json(order);
});

app.put('/api/orders/:id/status', (req, res) => {
  const order = DB.orders.find(o => o.id === req.params.id);
  if (order) {
    const { action, userName, notes } = req.body;
    
    if (action === 'approve') {
        order.approvalStatus = 'approved';
        order.paymentLink = `https://pay.guthmi.com/${order.id}`;
    }
    if (action === 'reject') order.approvalStatus = 'rejected';
    
    order.history.push({
      id: 'h_' + Date.now(),
      action,
      userName,
      timestamp: new Date().toISOString(),
      notes
    });
    res.json(order);
  } else res.status(404).send();
});

app.put('/api/orders/:id', (req, res) => {
    const idx = DB.orders.findIndex(o => o.id === req.params.id);
    if (idx > -1) {
        // Merge updates
        const { updates, userName } = req.body;
        DB.orders[idx] = { ...DB.orders[idx], ...updates };
        DB.orders[idx].history.push({
            id: 'h_' + Date.now(),
            action: 'updated',
            userName: userName || 'System',
            timestamp: new Date().toISOString()
        });
        res.json(DB.orders[idx]);
    } else res.status(404).send();
});

app.post('/api/orders/:id/invoice', (req, res) => {
    const order = DB.orders.find(o => o.id === req.params.id);
    if(order) {
        order.invoice = {
            id: 'inv_' + order.id,
            number: 'INV-' + order.orderNumber,
            url: 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf', // Mock PDF
            generatedAt: new Date().toISOString(),
            status: 'issued'
        };
        res.json({ url: order.invoice.url });
    } else res.status(404).send();
});

// 6. ANALYTICS & DASHBOARD
app.get('/api/analytics/summary', (req, res) => {
  const totalMessages = Object.values(DB.messages).flat().length;
  res.json({
    totalMessages: totalMessages,
    readRate: 85,
    failedRate: 2.5,
    totalCost: totalMessages * 0.05,
    deliveredRate: 98,
    activeConversations: DB.conversations.length,
    trends: { messages: 12, read: 5, cost: 8 }
  });
});

app.get('/api/analytics/timeline', (req, res) => {
  const days = 7;
  const data = [];
  for (let i = 0; i < days; i++) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    data.push({
      date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      sent: Math.floor(Math.random() * 100) + 50,
      delivered: Math.floor(Math.random() * 80) + 40,
      read: Math.floor(Math.random() * 60) + 20,
      failed: Math.floor(Math.random() * 5)
    });
  }
  res.json(data.reverse());
});

app.get('/api/system/queue-stats', (req, res) => {
  // Fluctuate random stats for liveness
  DB.queue.pending = Math.max(0, DB.queue.pending + (Math.random() > 0.5 ? 1 : -1));
  DB.queue.currentRate = Math.random() * 5;
  res.json(DB.queue);
});

app.get('/api/settings/protection', (req, res) => {
  res.json(DB.protection);
});

app.put('/api/settings/protection', (req, res) => {
  DB.protection = { ...DB.protection, ...req.body };
  res.json(DB.protection);
});

// 7. GLOBAL SETTINGS
app.get('/api/settings/global', (req, res) => {
    res.json(DB.globalSettings);
});

app.put('/api/settings/global', (req, res) => {
    DB.globalSettings = { ...DB.globalSettings, ...req.body };
    res.json(DB.globalSettings);
});

// 8. TEMPLATES & INTERNAL NOTIFS
app.get('/api/templates', async (req, res) => {
  if (WABA_ID && META_ACCESS_TOKEN) {
    try {
      const response = await metaClient.get(`/${WABA_ID}/message_templates`);
      res.json(response.data.data || []);
      return;
    } catch (e) {
      console.error('Meta Template Fetch Failed');
    }
  }
  // Return mock if no keys or failed
  res.json(DB.templates);
});

app.get('/api/internal-notifications', (req, res) => {
  res.json(DB.internalNotifications.reverse());
});

app.post('/api/internal-notifications', (req, res) => {
  const n = { id: 'n_' + Date.now(), read: false, timestamp: new Date().toISOString(), ...req.body };
  DB.internalNotifications.push(n);
  res.json(n);
});

app.post('/api/internal-notifications/:id/read', (req, res) => {
  if (req.params.id === 'all') {
    DB.internalNotifications.forEach(n => n.read = true);
  } else {
    const n = DB.internalNotifications.find(x => x.id === req.params.id);
    if (n) n.read = true;
  }
  res.json({ success: true });
});

app.get('/api/products', (req, res) => {
    const q = (req.query.q || '').toString().toLowerCase();
    const filtered = DB.products.filter(p => p.name.toLowerCase().includes(q) || p.sku.toLowerCase().includes(q));
    res.json(filtered);
});

// --- SERVER START ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`📦 Database initialized with ${DB.users.length} users, ${DB.contacts.length} contacts.`);
});
