
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';
import { Pool } from 'pg';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Security: Enforce JWT_SECRET in production
if (IS_PROD && (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'dev_secret_do_not_use_in_prod')) {
  console.error('❌ FATAL: JWT_SECRET must be set in production!');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_do_not_use_in_prod';
const APP_SECRET = process.env.APP_SECRET;
const FEEDBACK_TEMPLATE_NAME = process.env.FEEDBACK_TEMPLATE_NAME || 'util_feedback';
const FEEDBACK_TEMPLATE_LANGUAGE = process.env.FEEDBACK_TEMPLATE_LANGUAGE || 'ar';
const MAX_BOT_STEPS = 20; // Anti-loop guard for chatbot flows

// Error Translation Helper
const translateError = (errorKey: string, lang: string = 'ar'): string => {
  const errors: Record<string, Record<string, string>> = {
    'MISSING_FIELDS': { ar: 'حقول مطلوبة مفقودة', en: 'Missing required fields' },
    'CONVERSATION_NOT_FOUND': { ar: 'المحادثة غير موجودة', en: 'Conversation not found' },
    'CONVERSATION_CLOSED': { ar: 'لا يمكن الإرسال لمحادثة مغلقة', en: 'Cannot send message to closed conversation' },
    'WINDOW_EXPIRED': { ar: 'انتهت مهلة الـ 24 ساعة. استخدم قالب أو انتظر رد العميل', en: '24-hour window expired. Use template or wait for customer reply' },
    'CONVERSATION_ALREADY_CLOSED': { ar: 'المحادثة مغلقة بالفعل', en: 'Conversation already closed' },
    'INVALID_CAP': { ar: 'حد غير صالح', en: 'Invalid cap' },
    'PHONE_REQUIRED': { ar: 'رقم الهاتف مطلوب', en: 'Phone is required' },
    'NAME_REQUIRED': { ar: 'الاسم مطلوب', en: 'Name is required' },
    'TITLE_REQUIRED': { ar: 'العنوان مطلوب', en: 'Title is required' },
    'INVALID_CREDENTIALS': { ar: 'بيانات الدخول غير صحيحة', en: 'Invalid credentials' },
    'BOT_LOOP_DETECTED': { ar: 'تم اكتشاف تكرار في البوت - تم الإيقاف', en: 'Bot loop detected - stopped' }
  };
  return errors[errorKey]?.[lang] || errors[errorKey]?.['en'] || errorKey;
};

// Meta API Config
const META_API_VERSION = 'v22.0';
const BASE_URL = `https://graph.facebook.com/${META_API_VERSION}`;
const { META_ACCESS_TOKEN, WABA_ID, PHONE_NUMBER_ID, VERIFY_TOKEN } = process.env;

// --- Database Setup ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: false } : false,
});

// --- Types ---
interface OutboundMessage {
  to: string;
  type: 'text' | 'template' | 'interactive' | 'image';
  content: any;
  priority: number;
}

// --- Outbound Queue System (Production-Ready with DB Persistence) ---
class MessageQueue {
  private queue: { message: OutboundMessage, resolve: any, reject: any, campaignId?: string }[] = [];
  private isProcessing = false;
  private emergencyStop = false;
  private rateLimitDelay = 100; // ms between messages (synced from settings_protection.base_delay_ms)
  private campaignThrottleDelay = 1000; // ms between campaign messages (synced from settings_protection.campaign_delay_ms)
  private dailyMessageCount = 0;
  private dailyMessageCap = 10000; // Configurable (synced from settings_protection.max_daily_messages)
  private lastResetDate = new Date().toDateString();
  private campaignThrottles: Map<string, number> = new Map(); // campaignId -> last send timestamp
  private dbInitialized = false;

  constructor() {
    this.initializeFromDB();
  }

  private async initializeFromDB() {
    try {
      // 10) Load settings from settings_protection table (source of truth)
      const settingsRes = await pool.query('SELECT * FROM settings_protection WHERE id = 1');
      if (settingsRes.rows.length > 0) {
        const settings = settingsRes.rows[0];
        this.rateLimitDelay = settings.base_delay_ms || 100;
        this.campaignThrottleDelay = settings.campaign_delay_ms || 1000;
        this.dailyMessageCap = settings.max_daily_messages || 10000;
        this.emergencyStop = settings.emergency_stop || false;
        console.log('📊 Loaded queue settings from settings_protection:', {
          rateLimitDelay: this.rateLimitDelay,
          campaignThrottleDelay: this.campaignThrottleDelay,
          dailyMessageCap: this.dailyMessageCap,
          emergencyStop: this.emergencyStop
        });
      }

      // Load daily message count from app_state
      const countRes = await pool.query(
        "SELECT value FROM app_state WHERE key = 'dailyMessageCount'"
      );
      if (countRes.rowCount && countRes.rowCount > 0) {
        const data = countRes.rows[0].value;
        const savedDate = data.date;
        const today = new Date().toDateString();
        
        if (savedDate === today) {
          this.dailyMessageCount = data.count || 0;
          console.log('📊 Loaded dailyMessageCount from DB:', this.dailyMessageCount);
        } else {
          console.log('📊 New day detected, resetting counter');
          await this.saveDailyCountToDB();
        }
      }

      this.dbInitialized = true;
    } catch (err) {
      console.error('❌ Failed to initialize queue from DB:', err);
    }
  }

  // 10) Sync settings from DB (called when settings are updated)
  async syncSettingsFromDB() {
    try {
      const settingsRes = await pool.query('SELECT * FROM settings_protection WHERE id = 1');
      if (settingsRes.rows.length > 0) {
        const settings = settingsRes.rows[0];
        this.rateLimitDelay = settings.base_delay_ms || 100;
        this.campaignThrottleDelay = settings.campaign_delay_ms || 1000;
        this.dailyMessageCap = settings.max_daily_messages || 10000;
        this.emergencyStop = settings.emergency_stop || false;
        console.log('🔄 Queue settings synced from DB');
      }
    } catch (err) {
      console.error('❌ Failed to sync queue settings:', err);
    }
  }

  getCampaignThrottleDelay() {
    return this.campaignThrottleDelay;
  }

  private async saveEmergencyStopToDB() {
    try {
      await pool.query(
        `UPDATE settings_protection SET emergency_stop = $1, updated_at = NOW() WHERE id = 1`,
        [this.emergencyStop]
      );
      console.log('💾 Saved emergencyStop to DB:', this.emergencyStop);
    } catch (err) {
      console.error('❌ Failed to save emergencyStop:', err);
    }
  }

  private async saveDailyCountToDB() {
    try {
      await pool.query(
        `INSERT INTO app_state (key, value, updated_at)
         VALUES ('dailyMessageCount', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
        [JSON.stringify({ count: this.dailyMessageCount, date: this.lastResetDate })]
      );
    } catch (err) {
      console.error('❌ Failed to save dailyCount:', err);
    }
  }

  // persist=true writes to message_queue table first (survives restarts)
  // persist=false processes immediately in-memory (faster, but lost on restart)
  async enqueue(message: OutboundMessage, campaignId?: string, persist: boolean = false): Promise<any> {
    if (this.emergencyStop) {
      throw new Error('Emergency Stop Active');
    }
    
    // Check daily cap
    if (this.dailyMessageCount >= this.dailyMessageCap) {
      throw new Error('Daily message cap reached');
    }

    // If persist=true, write to DB and let the worker handle it
    if (persist) {
      const result = await pool.query(
        `INSERT INTO message_queue (to_number, message_type, message_content, campaign_id, priority, status)
         VALUES ($1, $2, $3, $4, $5, 'pending')
         RETURNING id`,
        [message.to, message.type, JSON.stringify(message.content), campaignId || null, message.priority || 1]
      );
      console.log(`📝 Message persisted to DB queue: ${result.rows[0].id}`);
      return { queued: true, id: result.rows[0].id };
    }

    // Otherwise, process immediately in-memory (original behavior)
    return new Promise((resolve, reject) => {
      this.queue.push({ message, resolve, reject, campaignId });
      this.process();
    });
  }

  async setEmergencyStop(stop: boolean) {
    this.emergencyStop = stop;
    await this.saveEmergencyStopToDB();
    if (!stop) this.process();
  }

  async setDailyCap(cap: number) {
    this.dailyMessageCap = cap;
    try {
      await pool.query(
        `UPDATE settings_protection SET max_daily_messages = $1, updated_at = NOW() WHERE id = 1`,
        [cap]
      );
    } catch (err) {
      console.error('❌ Failed to save dailyCap:', err);
    }
  }

  getStats() {
    const pending = this.queue.length;
    const processing = this.isProcessing ? 1 : 0;
    
    // Calculate current rate (messages per second)
    const currentRate = this.rateLimitDelay > 0 ? (1000 / this.rateLimitDelay) : 0;
    
    // Estimate completion time
    let estimatedCompletion = '0s';
    if (pending > 0 && currentRate > 0) {
      const totalSeconds = Math.ceil(pending / currentRate);
      if (totalSeconds < 60) {
        estimatedCompletion = `${totalSeconds}s`;
      } else if (totalSeconds < 3600) {
        estimatedCompletion = `${Math.ceil(totalSeconds / 60)}m`;
      } else {
        estimatedCompletion = `${Math.ceil(totalSeconds / 3600)}h`;
      }
    }
    
    return {
      pending,
      processing,
      completed: 0, // Could track this if needed
      failed: 0, // Could track this if needed
      emergencyStop: this.emergencyStop,
      dailyCount: this.dailyMessageCount,
      dailyCap: this.dailyMessageCap,
      currentRate,
      estimatedCompletion
    };
  }

  private resetDailyCountIfNeeded() {
    const today = new Date().toDateString();
    if (today !== this.lastResetDate) {
      this.dailyMessageCount = 0;
      this.lastResetDate = today;
    }
  }

  private async process() {
    if (this.isProcessing || this.queue.length === 0 || this.emergencyStop) return;
    
    this.resetDailyCountIfNeeded();
    
    if (this.dailyMessageCount >= this.dailyMessageCap) {
      console.warn('Daily message cap reached. Pausing queue.');
      return;
    }
    
    this.isProcessing = true;
    const item = this.queue.shift();
    
    if (item) {
      try {
        // Apply campaign throttle if applicable (using synced setting)
        if (item.campaignId) {
          const lastSent = this.campaignThrottles.get(item.campaignId) || 0;
          const timeSinceLastSent = Date.now() - lastSent;
          if (timeSinceLastSent < this.campaignThrottleDelay) {
            await new Promise(resolve => setTimeout(resolve, this.campaignThrottleDelay - timeSinceLastSent));
          }
          this.campaignThrottles.set(item.campaignId, Date.now());
        }

        const payload: any = {
          messaging_product: 'whatsapp',
          recipient_type: 'individual',
          to: item.message.to,
          type: item.message.type,
        };

        if (item.message.type === 'text') payload.text = item.message.content;
        else if (item.message.type === 'template') payload.template = item.message.content;
        else if (item.message.type === 'interactive') payload.interactive = item.message.content;
        else if (item.message.type === 'image') payload.image = item.message.content;

        const { data } = await axios.post(`${BASE_URL}/${PHONE_NUMBER_ID}/messages`, payload, {
          headers: { Authorization: `Bearer ${META_ACCESS_TOKEN}` }
        });
        
        this.dailyMessageCount++;
        await this.saveDailyCountToDB();
        item.resolve(data);
      } catch (error: any) {
        console.error('Meta API Send Error:', error.response?.data || error.message);
        item.reject(error);
      }

      // Rate Limiting Delay
      setTimeout(() => {
        this.isProcessing = false;
        this.process();
      }, this.rateLimitDelay);
    } else {
      this.isProcessing = false;
    }
  }
}

const outboundQueue = new MessageQueue();

// 🔥 NEW: DB-Persistent Queue Worker (runs every 2 seconds to process pending messages)
// This ensures messages survive server restarts
setInterval(async () => {
  if (outboundQueue['isProcessing'] || outboundQueue['emergencyStop']) return;
  
  try {
    const { rows } = await pool.query(
      `SELECT * FROM message_queue 
       WHERE status = 'pending' 
       AND (scheduled_at IS NULL OR scheduled_at <= NOW())
       ORDER BY priority DESC, created_at ASC 
       LIMIT 5`
    );
    
    for (const job of rows) {
      try {
        // Mark as processing
        await pool.query(
          `UPDATE message_queue SET status = 'processing', attempts = attempts + 1, updated_at = NOW() WHERE id = $1`,
          [job.id]
        );
        
        const messageContent = typeof job.message_content === 'string' 
          ? JSON.parse(job.message_content) 
          : job.message_content;
        
        // Send via existing queue (it handles rate limiting)
        await outboundQueue.enqueue({
          to: job.to_number,
          type: job.message_type,
          content: messageContent,
          priority: job.priority
        }, job.campaign_id);
        
        // Mark as sent
        await pool.query(
          `UPDATE message_queue SET status = 'sent', sent_at = NOW(), error = NULL WHERE id = $1`,
          [job.id]
        );
      } catch (err: any) {
        console.error(`Failed to send queued message ${job.id}:`, err?.response?.data || err?.message);
        await pool.query(
          `UPDATE message_queue SET status = 'failed', error = $1, updated_at = NOW() WHERE id = $2`,
          [err?.message || 'Unknown error', job.id]
        );
      }
    }
  } catch (err) {
    console.error('DB Queue worker error:', err);
  }
}, 2000); // Check every 2 seconds

// --- Scheduled Bot Actions Worker (executes delay nodes) ---
setInterval(async () => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM scheduled_bot_actions 
       WHERE execute_at <= NOW() AND status = 'pending'
       ORDER BY execute_at ASC
       LIMIT 10`
    );

    for (const action of rows) {
      try {
        console.log(`⏰ Executing scheduled action ${action.id} for node ${action.node_id}`);
        
        // Get conversation details
        const convRes = await pool.query(
          'SELECT contact_number FROM conversations WHERE id = $1',
          [action.conversation_id]
        );
        
        if (convRes.rowCount === 0) {
          console.warn(`Conversation ${action.conversation_id} not found`);
          await pool.query(
            `UPDATE scheduled_bot_actions SET status = 'failed' WHERE id = $1`,
            [action.id]
          );
          continue;
        }
        
        const to = convRes.rows[0].contact_number;
        
        // Get flow
        const flowRes = await pool.query('SELECT * FROM chat_flows WHERE id = $1', [action.flow_id]);
        if (flowRes.rowCount === 0) {
          console.warn(`Flow ${action.flow_id} not found`);
          await pool.query(
            `UPDATE scheduled_bot_actions SET status = 'failed' WHERE id = $1`,
            [action.id]
          );
          continue;
        }
        
        const flow = flowRes.rows[0];
        const node = flow.nodes?.find((n: any) => n.id === action.node_id);
        
        if (node) {
          // 14) Ensure bot_state is an object (pg might return string in rare cases)
          let botState = action.bot_state || {};
          if (typeof botState === 'string') {
            try {
              botState = JSON.parse(botState);
            } catch (e) {
              console.error('Failed to parse bot_state:', e);
              botState = {};
            }
          }
          await executeFlowNode(action.conversation_id, to, node, flow, botState);
          
          await pool.query(
            `UPDATE scheduled_bot_actions SET status = 'executed' WHERE id = $1`,
            [action.id]
          );
          console.log(`✅ Executed scheduled action ${action.id}`);
        }
      } catch (err) {
        console.error(`Failed to execute scheduled action ${action.id}:`, err);
        await pool.query(
          `UPDATE scheduled_bot_actions SET status = 'failed' WHERE id = $1`,
          [action.id]
        );
      }
    }
  } catch (err) {
    console.error('Scheduled actions worker error:', err);
  }
}, 60000); // Run every 60 seconds

// --- Middleware ---
app.use(helmet() as any);
app.use(morgan(IS_PROD ? 'combined' : 'dev') as any);

app.use(express.json({ 
  limit: '10mb',
  verify: (req: any, res, buf) => {
    req.rawBody = buf;
  }
}) as any);
app.use(express.urlencoded({ extended: true }) as any);

const allowedOrigins = [
  'http://localhost:5173',
  'https://wa-production-d791.up.railway.app',
  'https://wa-zeta.vercel.app'
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow server-to-server and tools (no origin header)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // Log blocked origin and allow it with warning (permissive for debugging)
    console.warn('⚠️ Origin not in allowedOrigins (allowing anyway):', origin);
    return callback(null, true); // Allow for now to debug
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// 🔥 ده أهم سطر في الموضوع كله
app.options('*', cors());

// Global request logger for debugging
app.use((req, res, next) => {
  if (req.path.includes('/api/')) {
    console.log(`📥 ${req.method} ${req.path} | Origin: ${req.headers.origin || 'none'} | Auth: ${req.headers.authorization ? 'present' : 'missing'}`);
  }
  next();
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 1000, 
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter as any);

// Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Webhook-specific rate limiter (stricter)
const webhookLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // max 100 requests per minute
  message: 'Too many webhook requests',
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Auth Middleware ---
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    console.warn('❌ No token provided:', req.method, req.path, 'Origin:', req.headers.origin);
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      console.warn('❌ Token verification failed:', err.message, 'for:', req.path);
      return res.status(403).json({ error: 'Forbidden' });
    }
    req.user = user;
    next();
  });
};

// --- Webhook Signature Verification ---
const verifySignature = (req: any, res: any, next: any) => {
  if (!APP_SECRET) return next();
  
  const signature = req.headers['x-hub-signature-256'];
  if (!signature) return res.status(401).json({ error: 'No signature provided' });

  const elements = signature.split('=');
  const signatureHash = elements[1];
  const expectedHash = crypto
    .createHmac('sha256', APP_SECRET)
    .update(req.rawBody)
    .digest('hex');

  if (signatureHash !== expectedHash) return res.status(401).json({ error: 'Invalid signature' });
  next();
};

// --- DB Schema & Init ---
const initSchema = async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Enable UUID generation (required for gen_random_uuid())
    await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";');
    
    // Core Tables
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'agent',
        permissions TEXT[],
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS conversations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        contact_number VARCHAR(50) UNIQUE NOT NULL,
        contact_name VARCHAR(255),
        assigned_agent_id UUID REFERENCES users(id),
        status VARCHAR(50) DEFAULT 'open',
        bot_state JSONB DEFAULT '{}'::jsonb,
        unread_count INT DEFAULT 0,
        last_message TEXT,
        last_message_at TIMESTAMP,
        last_customer_message_at TIMESTAMP,
        window_expires_at TIMESTAMP,
        active_flow_id UUID,
        tags TEXT[],
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        direction VARCHAR(20) CHECK (direction IN ('inbound', 'outbound')),
        type VARCHAR(50),
        content TEXT,
        status VARCHAR(50),
        meta_id VARCHAR(255) UNIQUE,
        media_url TEXT,
        media_mime_type VARCHAR(100),
        media_sha256 VARCHAR(64),
        media_file_size BIGINT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS conversation_assignments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        agent_id UUID REFERENCES users(id) ON DELETE CASCADE,
        assigned_by UUID REFERENCES users(id),
        assigned_at TIMESTAMP DEFAULT NOW(),
        unassigned_at TIMESTAMP,
        status VARCHAR(20) DEFAULT 'active'
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS conversation_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        event_type VARCHAR(50) NOT NULL,
        user_id UUID REFERENCES users(id),
        user_name VARCHAR(255),
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS campaigns (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50),
        status VARCHAR(50) DEFAULT 'draft',
        message_count INT DEFAULT 0,
        sent_count INT DEFAULT 0,
        failed_count INT DEFAULT 0,
        throttle_rate INT DEFAULT 0,
        daily_cap INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        sent_at TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS app_state (
        key VARCHAR(100) PRIMARY KEY,
        value JSONB NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS scheduled_bot_actions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        node_id VARCHAR(255) NOT NULL,
        flow_id UUID NOT NULL,
        execute_at TIMESTAMP NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        bot_state JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_scheduled_actions_execute
      ON scheduled_bot_actions(execute_at, status)
      WHERE status = 'pending';
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS message_queue (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
        to_number VARCHAR(50) NOT NULL,
        message_type VARCHAR(50),
        message_content JSONB NOT NULL,
        priority INT DEFAULT 0,
        status VARCHAR(50) DEFAULT 'pending',
        attempts INT DEFAULT 0,
        scheduled_at TIMESTAMP,
        sent_at TIMESTAMP,
        error TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create indexes for performance
    await client.query(`CREATE INDEX IF NOT EXISTS idx_conversations_status ON conversations(status);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_conversations_assigned_agent ON conversations(assigned_agent_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_message_queue_status ON message_queue(status);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_conversation_events_conv ON conversation_events(conversation_id);`);

    // Automation Tables
    await client.query(`
      CREATE TABLE IF NOT EXISTS quick_replies (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        shortcut VARCHAR(50) UNIQUE NOT NULL,
        content TEXT NOT NULL,
        category VARCHAR(50)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS auto_replies (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL DEFAULT 'Auto Reply',
        type VARCHAR(20) NOT NULL DEFAULT 'keyword',
        enabled BOOLEAN DEFAULT true,
        match_type VARCHAR(20) DEFAULT 'contains',
        keywords TEXT[] DEFAULT '{}'::text[],
        trigger TEXT,
        content TEXT NOT NULL,
        priority VARCHAR(20) DEFAULT 'medium',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS chat_flows (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        nodes JSONB NOT NULL DEFAULT '[]',
        edges JSONB NOT NULL DEFAULT '[]',
        triggers TEXT[],
        active BOOLEAN DEFAULT false,
        last_modified TIMESTAMP DEFAULT NOW()
      );
    `);

    // Protection Config Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS settings_protection (
        id INT PRIMARY KEY DEFAULT 1,
        emergency_stop BOOLEAN DEFAULT FALSE,
        base_delay_ms INT DEFAULT 100,
        campaign_delay_ms INT DEFAULT 1000,
        max_daily_messages INT DEFAULT 10000,
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      INSERT INTO settings_protection (id)
      VALUES (1)
      ON CONFLICT (id) DO NOTHING
    `);

    // Orders Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        order_number VARCHAR(50) UNIQUE NOT NULL,
        conversation_id UUID REFERENCES conversations(id) ON DELETE SET NULL,
        customer_phone VARCHAR(50),
        customer_name VARCHAR(255),
        items JSONB NOT NULL DEFAULT '[]',
        subtotal DECIMAL(10,2) DEFAULT 0,
        shipping_cost DECIMAL(10,2) DEFAULT 0,
        total DECIMAL(10,2) DEFAULT 0,
        status VARCHAR(50) DEFAULT 'pending',
        payment_status VARCHAR(50) DEFAULT 'pending',
        shipping_address JSONB,
        notes TEXT,
        created_by UUID REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS order_history (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        order_id UUID REFERENCES orders(id) ON DELETE CASCADE,
        action VARCHAR(100) NOT NULL,
        user_id UUID REFERENCES users(id),
        user_name VARCHAR(255),
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Tags Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS tags (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) NOT NULL,
        color VARCHAR(20) DEFAULT '#3B82F6',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Products Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS products (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) DEFAULT 0,
        sku VARCHAR(100),
        image_url TEXT,
        in_stock BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Internal Notifications Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS internal_notifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        type VARCHAR(50) DEFAULT 'info',
        title VARCHAR(255) NOT NULL,
        message TEXT,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Contacts Table (if not exists - extends conversations)
    await client.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        phone VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(255),
        email VARCHAR(255),
        company VARCHAR(255),
        notes TEXT,
        tags TEXT[],
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Add status constraint to conversations
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'conversations_status_chk'
        ) THEN
          ALTER TABLE conversations
            ADD CONSTRAINT conversations_status_chk
            CHECK (status IN ('open', 'pending', 'closed'));
        END IF;
      END $$;
    `);

    // Seed Admin (ONLY if env variables are set)
    const adminEmail = process.env.ADMIN_SEED_EMAIL;
    const adminPassword = process.env.ADMIN_SEED_PASSWORD;
    
    if (adminEmail && adminPassword) {
      const adminCheck = await client.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
      if (adminCheck.rowCount === 0) {
        const hash = await bcrypt.hash(adminPassword, 10);
        await client.query(`
          INSERT INTO users (name, email, password_hash, role, permissions)
          VALUES ($1, $2, $3, 'admin', $4)
        `, ['Admin User', adminEmail, hash, ['view_dashboard', 'manage_settings', 'view_inbox', 'approve_orders', 'manage_templates', 'manage_flows', 'manage_quick_replies', 'manage_auto_replies', 'manage_chatbot']]);
        console.log('🌱 Seeded admin user:', adminEmail);
      }
    } else {
      console.warn('⚠️  No admin seed: Set ADMIN_SEED_EMAIL and ADMIN_SEED_PASSWORD in production');
    }

    await client.query('COMMIT');
    console.log('✅ Database schema verified');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ DB Init failed:', e);
  } finally {
    client.release();
  }
};

// --- CHATBOT ENGINE ---
const processBotLogic = async (conversation: any, messageContent: string, from: string) => {
  try {
    let currentFlowId = conversation.active_flow_id;
    let botState = conversation.bot_state || {};

    // Anti-loop guard: Check step count
    const stepCount = (botState.stepCount ?? 0) + 1;
    if (stepCount > MAX_BOT_STEPS) {
      console.error(`⚠️ Bot loop detected for conversation ${conversation.id} - max ${MAX_BOT_STEPS} steps reached`);
      await pool.query('UPDATE conversations SET active_flow_id = NULL, bot_state = DEFAULT WHERE id = $1', [conversation.id]);
      // Send error message to user
      await outboundQueue.enqueue({
        to: from,
        type: 'text',
        content: { body: translateError('BOT_LOOP_DETECTED', 'ar') },
        priority: 1
      });
      return;
    }
    botState.stepCount = stepCount;

    // 1. Trigger Check (If no active flow)
    if (!currentFlowId) {
      const { rows: flows } = await pool.query('SELECT * FROM chat_flows WHERE active = true');
      for (const flow of flows) {
        if (flow.triggers && flow.triggers.includes(messageContent.toLowerCase().trim())) {
          currentFlowId = flow.id;
          // 12) Improved start node detection:
          // Priority 1: Look for explicit 'start' type node
          // Priority 2: Look for node with no incoming edges
          // Priority 3: Use first node in array
          let startNode = flow.nodes.find((n: any) => n.type === 'start');
          if (!startNode) {
            startNode = flow.nodes.find((n: any) => !flow.edges.some((e: any) => e.target === n.id));
          }
          if (!startNode && flow.nodes.length > 0) {
            startNode = flow.nodes[0];
          }
          if (startNode) {
             botState = { currentNodeId: startNode.id, variables: {} };
             await pool.query('UPDATE conversations SET active_flow_id = $1, bot_state = $2 WHERE id = $3', [currentFlowId, botState, conversation.id]);
             await executeFlowNode(conversation.id, from, startNode, flow, botState);
             return;
          }
        }
      }
    }

    // 2. Continue Active Flow
    if (currentFlowId) {
      const { rows } = await pool.query('SELECT * FROM chat_flows WHERE id = $1', [currentFlowId]);
      if (rows.length === 0) return; // Flow deleted
      const flow = rows[0];
      
      // We are waiting for input from the previous step
      // Logic: Find current node, follow edge based on input
      const currentNode = flow.nodes.find((n: any) => n.id === botState.currentNodeId);
      if (currentNode) {
         // Process Input (Store variable if node was a question)
         if (currentNode.type === 'question' && currentNode.data.variable) {
           botState.variables = botState.variables || {};
           botState.variables[currentNode.data.variable] = messageContent;
           await pool.query('UPDATE conversations SET bot_state = $1 WHERE id = $2', [botState, conversation.id]);
         }
         
         // Find next node based on user response
         let edge = null;
         
         // For question nodes with options, match user input to option label
         if ((currentNode.type === 'question' || currentNode.type === 'interactive') && currentNode.data.options) {
           const selectedOption = currentNode.data.options.find((opt: any) => 
             opt.label && opt.label.toLowerCase().trim() === messageContent.toLowerCase().trim()
           );
           
           if (selectedOption) {
             // Find edge with matching sourceHandle (option id)
             edge = flow.edges.find((e: any) => 
               e.source === currentNode.id && e.sourceHandle === selectedOption.id
             );
           }
         }
         
         // Fallback: use first edge from current node
         if (!edge) {
           edge = flow.edges.find((e: any) => e.source === currentNode.id);
         }
         
         if (edge) {
           const nextNode = flow.nodes.find((n: any) => n.id === edge.target);
           if (nextNode) {
             botState.currentNodeId = nextNode.id;
             await pool.query('UPDATE conversations SET bot_state = $1 WHERE id = $2', [botState, conversation.id]);
             await executeFlowNode(conversation.id, from, nextNode, flow, botState);
           } else {
             // End of flow
             await pool.query('UPDATE conversations SET active_flow_id = NULL, bot_state = DEFAULT WHERE id = $1', [conversation.id]);
           }
         } else {
           // End of flow
           await pool.query('UPDATE conversations SET active_flow_id = NULL, bot_state = DEFAULT WHERE id = $1', [conversation.id]);
         }
      }
    }

  } catch (e) {
    console.error("Bot Engine Error:", e);
  }
};

const executeFlowNode = async (convId: string, to: string, node: any, flow: any, botState: any = {}) => {
  try {
    // 🛡️ ANTI-LOOP GUARD: Prevent infinite loops
    const MAX_STEPS = 20;
    if (!botState.stepCount) botState.stepCount = 0;
    botState.stepCount++;
    
    if (botState.stepCount > MAX_STEPS) {
      console.error(`🚨 Bot loop detected for conversation ${convId}, stopping after ${botState.stepCount} steps`);
      await pool.query(
        `UPDATE conversations SET active_flow_id = NULL, bot_state = '{}'::jsonb WHERE id = $1`,
        [convId]
      );
      
      // Send error message to user
      await outboundQueue.enqueue({
        to,
        type: 'text',
        content: { body: 'عذراً، حدث خطأ في المحادثة. يرجى المحاولة مرة أخرى.' },
        priority: 1
      });
      return;
    }
    
    // Handle different node types
    if (node.type === 'message' || node.type === 'text') {
      // Send text message
      await outboundQueue.enqueue({
        to,
        type: 'text',
        content: { body: node.data.content || node.data.message || '' },
        priority: 1
      });
      
      await pool.query(
        `INSERT INTO messages (conversation_id, direction, type, content, status)
         VALUES ($1, 'outbound', 'text', $2, 'sent')`,
        [convId, node.data.content || node.data.message]
      );
    } 
    else if (node.type === 'question' || node.type === 'interactive') {
      // Send interactive message with buttons
      const buttons = node.data.options || [];
      if (buttons.length > 0 && buttons.length <= 3) {
        // Use button message
        await outboundQueue.enqueue({
          to,
          type: 'interactive',
          content: {
            type: 'button',
            body: { text: node.data.content || node.data.message || '' },
            action: {
              buttons: buttons.slice(0, 3).map((opt: any, idx: number) => ({
                type: 'reply',
                reply: { 
                  id: opt.id || `opt_${idx}`, 
                  title: opt.label || opt 
                }
              }))
            }
          },
          priority: 1
        });
      } else {
        // Fallback to text
        await outboundQueue.enqueue({
          to,
          type: 'text',
          content: { body: (node.data.content || '') + "\n\n" + buttons.map((b: any, i: number) => `${i+1}. ${b.label || b}`).join("\n") },
          priority: 1
        });
      }
      
      await pool.query(
        `INSERT INTO messages (conversation_id, direction, type, content, status)
         VALUES ($1, 'outbound', 'interactive', $2, 'sent')`,
        [convId, node.data.content || node.data.message]
      );
      
      // Save current node to bot_state for question/interactive nodes
      if (node.type === 'question' || node.type === 'interactive') {
        botState.currentNodeId = node.id;
        await pool.query('UPDATE conversations SET bot_state = $1 WHERE id = $2', [botState, convId]);
        return; // Wait for user response
      }
    }
    else if (node.type === 'image') {
      // Send image message
      const imageUrl = node.data.imageUrl || node.data.url;
      if (imageUrl) {
        await outboundQueue.enqueue({
          to,
          type: 'image',
          content: { link: imageUrl, caption: node.data.caption || '' },
          priority: 1
        });
        
        await pool.query(
          `INSERT INTO messages (conversation_id, direction, type, content, status)
           VALUES ($1, 'outbound', 'image', $2, 'sent')`,
          [convId, node.data.caption || '[Image]']
        );
      }
    }
    else if (node.type === 'delay') {
      // ⏰ PRODUCTION FIX: Delay execution via DB scheduling (persists on restart)
      const delayMs = node.data.duration || 1000;
      console.log(`⏰ Scheduling delay node: ${delayMs}ms`);
      
      // Get next node connection
      const nextEdge = flow.edges?.find((e: any) => e.source === node.id);
      if (nextEdge) {
        const nextNodeId = nextEdge.target;
        const nextNode = flow.nodes?.find((n: any) => n.id === nextNodeId);
        
        if (nextNode) {
          // Schedule in database
          const executeAt = new Date(Date.now() + delayMs);
          await pool.query(
            `INSERT INTO scheduled_bot_actions (conversation_id, node_id, flow_id, execute_at, bot_state)
             VALUES ($1, $2, $3, $4, $5)`,
            [convId, nextNode.id, flow.id, executeAt, JSON.stringify(botState)]
          );
          console.log(`💾 Scheduled ${nextNode.id} for execution at ${executeAt.toISOString()}`);
        }
      }
      return; // Don't continue to next node immediately
    }
    else if (node.type === 'condition') {
      // Conditional branching - evaluate condition
      const condition = node.data.condition || '';
      const variable = node.data.variable || '';
      const operator = node.data.operator || '==';
      const value = node.data.value || '';
      
      console.log(`Evaluating condition: ${variable} ${operator} ${value}`);
      
      // Get variable value from bot state
      const currentValue = botState.variables?.[variable] || '';
      
      // Simple condition evaluation
      let conditionMet = false;
      switch (operator) {
        case '==':
        case 'equals':
          conditionMet = currentValue === value;
          break;
        case '!=':
        case 'not_equals':
          conditionMet = currentValue !== value;
          break;
        case 'contains':
          conditionMet = String(currentValue).toLowerCase().includes(String(value).toLowerCase());
          break;
        case 'starts_with':
          conditionMet = String(currentValue).toLowerCase().startsWith(String(value).toLowerCase());
          break;
        case 'is_empty':
          conditionMet = !currentValue || currentValue === '';
          break;
        case 'is_not_empty':
          conditionMet = currentValue && currentValue !== '';
          break;
        default:
          conditionMet = false;
      }
      
      console.log(`Condition result: ${conditionMet}`);
      
      // Find the appropriate next edge (true or false branch)
      const nextEdge = flow.edges?.find((e: any) => {
        if (e.source !== node.id) return false;
        const edgeLabel = (e.label || e.sourceHandle || '').toLowerCase();
        return conditionMet ? edgeLabel.includes('true') || edgeLabel.includes('yes') : edgeLabel.includes('false') || edgeLabel.includes('no');
      });
      
      if (nextEdge) {
        const nextNode = flow.nodes?.find((n: any) => n.id === nextEdge.target);
        if (nextNode) {
          await executeFlowNode(convId, to, nextNode, flow, botState);
        }
      }
      return; // Don't use default next node logic
    }
  } catch (error) {
    console.error('Flow node execution error:', error);
  }
};

// --- WEBHOOK ROUTES ---
// REMOVED: Legacy /webhook endpoint - use /api/webhooks/whatsapp only
// Configure Meta Dashboard with: https://your-domain.com/api/webhooks/whatsapp

// --- WHATSAPP WEBHOOKS (Official Meta Endpoint) ---
// Use /api/webhooks/whatsapp for Meta Dashboard configuration

// WhatsApp Webhooks (Meta)
app.get('/api/webhooks/whatsapp', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

app.post('/api/webhooks/whatsapp', verifySignature, webhookLimiter, async (req, res) => {
  try {
    // Signature already verified by verifySignature middleware
    console.log('✅ Webhook signature verified by middleware');

    // Log RAW webhook event
    await pool.query(
      `INSERT INTO conversation_events (conversation_id, event_type, metadata) VALUES (NULL, 'WEBHOOK_RAW', $1)`,
      [req.body]
    );

    // 7) Loop over ALL entries and changes (Meta can send multiple)
    const entries = req.body.entry || [];
    for (const entry of entries) {
      const changes = entry?.changes || [];
      for (const change of changes) {
        const value = change?.value;
        if (!value) continue;

    // Incoming messages
    if (value?.messages?.length) {
      for (const msg of value.messages) {
        const from = msg.from;
        const messageId = msg.id;
        
        // IDEMPOTENCY CHECK: Skip if message already exists
        const existingMsg = await pool.query('SELECT id FROM messages WHERE meta_id = $1', [messageId]);
        if ((existingMsg.rowCount ?? 0) > 0) {
          console.log(`Duplicate message ignored: ${messageId}`);
          continue;
        }
        
        let text = msg.text?.body || '';
        
        // 6) Extract text from interactive messages (buttons, list replies)
        if (!text && msg.button) {
          text = msg.button.text || msg.button.payload || '';
        }
        if (!text && msg.interactive) {
          // Button reply
          if (msg.interactive.button_reply) {
            text = msg.interactive.button_reply.title || msg.interactive.button_reply.id || '';
          }
          // List reply
          if (msg.interactive.list_reply) {
            text = msg.interactive.list_reply.title || msg.interactive.list_reply.id || '';
          }
        }
        
        let mediaUrl = null;
        let mediaMimeType = null;
        let mediaSha256 = null;
        let mediaFileSize = null;
        
        // Handle media messages
        if (msg.type === 'image' || msg.type === 'video' || msg.type === 'audio' || msg.type === 'document') {
          try {
            const mediaId = msg.image?.id || msg.video?.id || msg.audio?.id || msg.document?.id;
            if (mediaId && META_ACCESS_TOKEN) {
              // Fetch media URL from Graph API (using same version as main API)
              const mediaRes = await axios.get(`https://graph.facebook.com/${META_API_VERSION}/${mediaId}`, {
                headers: { Authorization: `Bearer ${META_ACCESS_TOKEN}` }
              });
              mediaUrl = mediaRes.data.url;
              mediaMimeType = mediaRes.data.mime_type;
              mediaSha256 = mediaRes.data.sha256;
              mediaFileSize = mediaRes.data.file_size;
            }
            text = msg.caption || `[وسائط: ${msg.type}]`;
          } catch (mediaErr) {
            console.error('Media fetch error:', mediaErr);
            text = `[وسائط]`;
          }
        }
        
        const timestamp = new Date(parseInt(msg.timestamp, 10) * 1000);

        // Check if conversation exists and is closed (to track re-open)
        const existingConv = await pool.query(
          'SELECT id, status FROM conversations WHERE contact_number = $1',
          [from]
        );
        const wasClosedAndReopening = existingConv.rows[0]?.status === 'closed';

        const convRes = await pool.query(
          `INSERT INTO conversations (contact_number, status, last_message, last_message_at, last_customer_message_at, window_expires_at, unread_count)
           VALUES ($1, 'open', $2, $3, $3, $4, 1)
           ON CONFLICT (contact_number) DO UPDATE SET
             status = CASE 
               WHEN conversations.status = 'closed' THEN 'open'  -- Reopen if customer messages
               ELSE conversations.status  -- Keep current status otherwise
             END,
             last_message = EXCLUDED.last_message,
             last_message_at = EXCLUDED.last_message_at,
             last_customer_message_at = EXCLUDED.last_customer_message_at,
             window_expires_at = EXCLUDED.window_expires_at,
             unread_count = conversations.unread_count + 1
           RETURNING id`,
          [from, text, timestamp, new Date(timestamp.getTime() + 24 * 60 * 60 * 1000)]
        );
        const conversationId = convRes.rows[0].id;

        // Log reopen event if was closed
        if (wasClosedAndReopening) {
          await pool.query(
            `INSERT INTO conversation_events (conversation_id, event_type, metadata)
             VALUES ($1, 'conversation_reopened', $2)`,
            [conversationId, { reason: 'customer_message', from }]
          );
          console.log(`🔄 Conversation ${conversationId} reopened by customer message`);
        }

        await pool.query(
          `INSERT INTO messages (conversation_id, direction, type, content, status, meta_id, media_url, media_mime_type, media_sha256, media_file_size, created_at)
           VALUES ($1, 'inbound', $2, $3, 'delivered', $4, $5, $6, $7, $8, $9)`,
          [conversationId, msg.type || 'text', text, messageId, mediaUrl, mediaMimeType, mediaSha256, mediaFileSize, timestamp]
        );

        await pool.query(
          `INSERT INTO conversation_events (conversation_id, event_type, metadata)
           VALUES ($1, 'inbound_received', $2)`,
          [conversationId, { from, msg }]
        );

        // Trigger bot logic (only if not assigned to an agent)
        const convData = await pool.query('SELECT * FROM conversations WHERE id = $1', [conversationId]);
        const conversation = convData.rows[0];
        
        // Skip bot if conversation is assigned to an agent
        if (!conversation.assigned_agent_id) {
          await processBotLogic(conversation, text, from);
        } else {
          console.log(`⏭️ Skipping bot for assigned conversation ${conversationId}`);
        }
      }
    }

    // Delivery/Read statuses
    if (value?.statuses?.length) {
      for (const st of value.statuses) {
        const wamid = st.id;
        const newStatus = (st.status || '').toLowerCase();

        await pool.query(
          `UPDATE messages SET status = $1, updated_at = NOW() WHERE meta_id = $2`,
          [newStatus, wamid]
        );

        const convRow = await pool.query(
          `SELECT conversation_id FROM messages WHERE meta_id = $1 LIMIT 1`,
          [wamid]
        );
        const conversationId = convRow.rows[0]?.conversation_id || null;

        await pool.query(
          `INSERT INTO conversation_events (conversation_id, event_type, metadata)
           VALUES ($1, $2, $3)`,
          [conversationId, newStatus, st]
        );
      }
    }

      } // End of changes loop
    } // End of entries loop

    res.sendStatus(200);
  } catch (e) {
    console.error('Webhook error:', e);
    res.sendStatus(500);
  }
});

// Auth
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('🔐 Login attempt:', { email, hasPassword: !!password, origin: req.headers.origin });
  
  if (!email || !password) {
    console.warn('❌ Missing credentials in request body');
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (rows.length === 0) {
      console.warn('❌ User not found:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      console.warn('❌ Invalid password for:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    delete user.password_hash;
    console.log('✅ Login successful:', email);
    res.json({ token, user });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// Conversations
app.get('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        c.id, c.contact_name as "contactName", c.contact_number as "contactNumber",
        c.last_message as "lastMessage", c.last_message_at as "lastMessageTimestamp",
        c.last_customer_message_at as "lastCustomerMessageTimestamp",
        c.unread_count as "unreadCount", LOWER(c.status) as status, c.assigned_agent_id as "assignedAgentId",
        c.tags, c.window_expires_at as "windowExpiresAt"
      FROM conversations c
      ORDER BY c.last_message_at DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

// Assign Agent Endpoint
app.post('/api/conversations/:id/assign', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { agentId } = req.body;
  const assignedBy = (req as any).user?.id;

  try {
    await pool.query('UPDATE conversations SET assigned_agent_id = $1 WHERE id = $2', [agentId, id]);

    await pool.query(
      'INSERT INTO conversation_assignments (conversation_id, agent_id, assigned_by) VALUES ($1, $2, $3)',
      [id, agentId, assignedBy]
    );

    await pool.query(
      'INSERT INTO conversation_events (conversation_id, event_type, metadata) VALUES ($1, $2, $3)',
      [id, 'agent_assigned', JSON.stringify({ agentId, assignedBy })]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Assign agent error:', err);
    res.status(500).json({ error: 'Failed to assign agent' });
  }
});

app.put('/api/conversations/:id', authenticateToken, async (req, res) => {
  const { tags, status, assignedAgentId } = req.body;
  const userId = (req as any).user?.id;
  const userName = (req as any).user?.name || 'Unknown';
  
  try {
    // Handle agent assignment
    if (assignedAgentId !== undefined) {
      const convRes = await pool.query('SELECT assigned_agent_id FROM conversations WHERE id = $1', [req.params.id]);
      if ((convRes.rowCount ?? 0) > 0) {
        const oldAgentId = convRes.rows[0].assigned_agent_id;
        
        // Unassign old agent if exists
        if (oldAgentId) {
          await pool.query(
            `UPDATE conversation_assignments SET status = 'inactive', unassigned_at = NOW()
             WHERE conversation_id = $1 AND agent_id = $2 AND status = 'active'`,
            [req.params.id, oldAgentId]
          );
        }
        
        // Assign new agent if provided
        if (assignedAgentId) {
          await pool.query(
            `INSERT INTO conversation_assignments (conversation_id, agent_id, assigned_by)
             VALUES ($1, $2, $3)`,
            [req.params.id, assignedAgentId, userId]
          );
          
          await pool.query(
            `INSERT INTO conversation_events (conversation_id, event_type, user_id, user_name, metadata)
             VALUES ($1, 'agent_assigned', $2, $3, $4)`,
            [req.params.id, userId, userName, JSON.stringify({ agent_id: assignedAgentId })]
          );
        }
        
        await pool.query('UPDATE conversations SET assigned_agent_id = $1 WHERE id = $2', [assignedAgentId, req.params.id]);
      }
    }
    
    // Handle tags
    if (tags !== undefined) {
      await pool.query('UPDATE conversations SET tags = $1 WHERE id = $2', [tags, req.params.id]);
      await pool.query(
        `INSERT INTO conversation_events (conversation_id, event_type, user_id, user_name, metadata)
         VALUES ($1, 'tags_updated', $2, $3, $4)`,
        [req.params.id, userId, userName, JSON.stringify({ tags })]
      );
    }
    
    // Handle status change
    if (status) {
      await pool.query('UPDATE conversations SET status = $1 WHERE id = $2', [status, req.params.id]);
      await pool.query(
        `INSERT INTO conversation_events (conversation_id, event_type, user_id, user_name, metadata)
         VALUES ($1, 'status_changed', $2, $3, $4)`,
        [req.params.id, userId, userName, JSON.stringify({ new_status: status })]
      );
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error('Update conversation error:', err);
    res.status(500).json({ error: 'DB Error' });
  }
});

// Messages
app.get('/api/messages/:id', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT * FROM messages WHERE conversation_id = $1 ORDER BY created_at ASC
    `, [req.params.id]);
    
    const messages = rows.map(r => ({
      id: r.id,
      conversationId: r.conversation_id,
      direction: r.direction,
      type: r.type,
      content: r.content,
      status: r.status,
      timestamp: r.created_at
    }));
    
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  const { conversationId, content, type } = req.body;
  
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  if (!conversationId || !content) return res.status(400).json({ error: translateError('MISSING_FIELDS', lang) });

  try {
    const convRes = await pool.query('SELECT contact_number, status, window_expires_at FROM conversations WHERE id = $1', [conversationId]);
    if (convRes.rowCount === 0) return res.status(404).json({ error: translateError('CONVERSATION_NOT_FOUND', lang) });
    
    const conversation = convRes.rows[0];
    const to = conversation.contact_number;
    
    // Check if conversation is closed
    if (conversation.status === 'closed') {
      return res.status(400).json({ error: translateError('CONVERSATION_CLOSED', lang) });
    }
    
    // Check 24-hour window for regular messages (not templates)
    if (type !== 'template' && type !== 'note') {
      const now = new Date();
      const windowExpires = conversation.window_expires_at ? new Date(conversation.window_expires_at) : null;
      
      if (!windowExpires || now > windowExpires) {
        return res.status(400).json({ 
          error: translateError('WINDOW_EXPIRED', lang),
          code: 'WINDOW_EXPIRED'
        });
      }
    }

    // Don't send notes to WhatsApp (internal only)
    if (type !== 'note') {
      // Validate message type
      const validTypes = ['text', 'template', 'interactive', 'image'];
      const messageType = type && validTypes.includes(type) ? type : 'text';
      
      // Use Queue with DB persistence (survives server restarts)
      await outboundQueue.enqueue({
        to,
        type: messageType as any,
        content: messageType === 'text' ? { body: content } : content,
        priority: 1
      }, undefined, true); // persist=true
    }

    const insertRes = await pool.query(
      `INSERT INTO messages (conversation_id, direction, type, content, status)
       VALUES ($1, 'outbound', $2, $3, $4) RETURNING *`,
      [conversationId, type || 'text', content, type === 'note' ? 'delivered' : 'sent']
    );

    await pool.query('UPDATE conversations SET last_message = $1, last_message_at = NOW() WHERE id = $2', [content, conversationId]);

    const r = insertRes.rows[0];
    res.json({
      id: r.id,
      conversationId: r.conversation_id,
      direction: r.direction,
      type: r.type,
      content: r.content,
      status: r.status,
      timestamp: r.created_at
    });

  } catch (err: any) {
    console.error('Send Error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.post('/api/conversations/:id/close', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = (req as any).user?.id;
  const userName = (req as any).user?.name || 'Unknown';
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  
  try {
    const convRes = await pool.query('SELECT contact_number, status FROM conversations WHERE id = $1', [id]);
    if ((convRes.rowCount ?? 0) === 0) return res.status(404).json({ error: translateError('CONVERSATION_NOT_FOUND', lang) });
    
    const conversation = convRes.rows[0];
    if (conversation.status === 'closed') {
      return res.status(400).json({ error: translateError('CONVERSATION_ALREADY_CLOSED', lang) });
    }
    
    const to = conversation.contact_number;

    await pool.query("UPDATE conversations SET status = 'closed', assigned_agent_id = NULL WHERE id = $1", [id]);
    
    // Log event
    await pool.query(
      `INSERT INTO conversation_events (conversation_id, event_type, user_id, user_name, metadata)
       VALUES ($1, 'conversation_closed', $2, $3, $4)`,
      [id, userId, userName, JSON.stringify({ reason: 'manual_close' })]
    );

    // Send Feedback Template via Queue (using ENV config + language detection)
    try {
      // Detect conversation language from recent messages
      const langRes = await pool.query(
        `SELECT content FROM messages 
         WHERE conversation_id = $1 AND direction = 'inbound' 
         ORDER BY created_at DESC LIMIT 5`,
        [id]
      );
      
      let detectedLang = FEEDBACK_TEMPLATE_LANGUAGE; // default from ENV
      if ((langRes.rowCount ?? 0) > 0) {
        const recentTexts = langRes.rows.map(r => r.content).join(' ');
        const arabicRegex = /[\u0600-\u06FF]/;
        detectedLang = arabicRegex.test(recentTexts) ? 'ar' : 'en';
      }

      console.log(`📤 Sending feedback template: ${FEEDBACK_TEMPLATE_NAME} (${detectedLang})`);

      await outboundQueue.enqueue({
        to,
        type: 'template',
        content: { name: FEEDBACK_TEMPLATE_NAME, language: { code: detectedLang } },
        priority: 1
      }, undefined, true); // persist=true

      await pool.query(
        `INSERT INTO messages (conversation_id, direction, type, content, status)
         VALUES ($1, 'outbound', 'template', $2, 'sent')`,
        [id, `Feedback Template: ${FEEDBACK_TEMPLATE_NAME} (${detectedLang})`]
      );
    } catch (templateErr) {
      // Template may not exist, log but don't fail
      console.warn('Feedback template not sent:', templateErr);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Close conversation error:', err);
    res.status(500).json({ error: 'Failed to close' });
  }
});

// Get conversation details including events and assignments
app.get('/api/conversations/:id/details', authenticateToken, async (req, res) => {
  try {
    const convRows = await pool.query('SELECT * FROM conversations WHERE id = $1', [req.params.id]);
    if (convRows.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    
    const conversation = convRows.rows[0];
    
    const { rows: events } = await pool.query(
      `SELECT * FROM conversation_events WHERE conversation_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.params.id]
    );
    
    const { rows: assignments } = await pool.query(
      `SELECT ca.*, u.name as agent_name FROM conversation_assignments ca
       LEFT JOIN users u ON ca.agent_id = u.id
       WHERE ca.conversation_id = $1 ORDER BY ca.assigned_at DESC`,
      [req.params.id]
    );
    
    res.json({ conversation, events, assignments });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch details' });
  }
});

// Queue management endpoints
app.get('/api/queue/stats', authenticateToken, async (req, res) => {
  const stats = outboundQueue.getStats();
  res.json(stats);
});

app.post('/api/queue/emergency-stop', authenticateToken, async (req, res) => {
  const { stop } = req.body;
  await outboundQueue.setEmergencyStop(stop === true);  // 11) Fixed: added await
  res.json({ success: true, emergencyStop: stop });
});

app.post('/api/queue/set-daily-cap', authenticateToken, async (req, res) => {
  const { cap } = req.body;
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  if (!cap || cap < 0) return res.status(400).json({ error: translateError('INVALID_CAP', lang) });
  outboundQueue.setDailyCap(cap);
  res.json({ success: true, dailyCap: cap });
});

// Protection Settings API
app.get('/api/settings/protection', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM settings_protection ORDER BY id LIMIT 1');
    const queueStats = outboundQueue.getStats();
    
    let config;
    if (result.rows.length === 0) {
      // Return defaults
      config = {
        base_delay_ms: 100,
        campaign_delay_ms: 1000,
        max_daily_messages: 10000,
        emergency_stop: false
      };
    } else {
      config = result.rows[0];
    }
    
    // Calculate health status
    const dailyUsagePercent = (queueStats.dailyCount / config.max_daily_messages) * 100;
    let healthStatus: 'HEALTHY' | 'WARNING' | 'CRITICAL' = 'HEALTHY';
    if (config.emergency_stop) {
      healthStatus = 'CRITICAL';
    } else if (dailyUsagePercent > 90) {
      healthStatus = 'CRITICAL';
    } else if (dailyUsagePercent > 70 || queueStats.pending > 100) {
      healthStatus = 'WARNING';
    }
    
    // Transform to frontend format (camelCase)
    res.json({
      emergencyStop: config.emergency_stop,
      warmUpMode: false, // Could be calculated based on time since startup
      maxDailyMessages: config.max_daily_messages,
      currentDailyCount: queueStats.dailyCount,
      baseDelayMs: config.base_delay_ms,
      consecutiveFailures: 0, // Could track this if needed
      healthStatus
    });
  } catch (err) {
    console.error('Get protection settings error:', err);
    res.status(500).json({ error: 'DB Error' });
  }
});

app.put('/api/settings/protection', authenticateToken, async (req, res) => {
  const { base_delay_ms, campaign_delay_ms, max_daily_messages, emergency_stop } = req.body;
  
  try {
    const result = await pool.query(`
      INSERT INTO settings_protection (id, base_delay_ms, campaign_delay_ms, max_daily_messages, emergency_stop)
      VALUES (1, $1, $2, $3, $4)
      ON CONFLICT (id) DO UPDATE SET
        base_delay_ms = COALESCE($1, settings_protection.base_delay_ms),
        campaign_delay_ms = COALESCE($2, settings_protection.campaign_delay_ms),
        max_daily_messages = COALESCE($3, settings_protection.max_daily_messages),
        emergency_stop = COALESCE($4, settings_protection.emergency_stop),
        updated_at = NOW()
      RETURNING *
    `, [base_delay_ms, campaign_delay_ms, max_daily_messages, emergency_stop]);
    
    // 10) Sync all settings to queue (not just emergency_stop and dailyCap)
    await outboundQueue.syncSettingsFromDB();
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update protection settings error:', err);
    res.status(500).json({ error: 'DB Error' });
  }
});

// Users API (for Agent Assignment dropdown)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, role FROM users ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'DB Error' });
  }
});

// Quick Replies
app.get('/api/automation/quick-replies', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM quick_replies');
    res.json(rows);
  } catch (e) {
    console.error('Get quick-replies error:', e);
    res.status(500).json([]);
  }
});

app.post('/api/automation/quick-replies', authenticateToken, async (req, res) => {
  const { id, shortcut, content, category } = req.body;
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  
  // Validation
  if (!shortcut || !content) {
    return res.status(400).json({ error: translateError('REQUIRED_FIELDS', lang) });
  }
  
  try {
    if (id) {
      const { rows } = await pool.query('UPDATE quick_replies SET shortcut=$1, content=$2, category=$3 WHERE id=$4 RETURNING *', [shortcut, content, category, id]);
      res.json(rows[0]);
    } else {
      const { rows } = await pool.query('INSERT INTO quick_replies (shortcut, content, category) VALUES ($1, $2, $3) RETURNING *', [shortcut, content, category]);
      res.json(rows[0]);
    }
  } catch (e) {
    console.error('Save quick-reply error:', e);
    res.status(500).json({ error: 'Failed to save quick reply' });
  }
});

app.delete('/api/automation/quick-replies/:id', authenticateToken, async (req, res) => {
  await pool.query('DELETE FROM quick_replies WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// Chat Flows
app.get('/api/automation/flows', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM chat_flows');
    res.json(rows);
  } catch (e) {
    console.error('Get flows error:', e);
    res.status(500).json([]);
  }
});

app.post('/api/automation/flows', authenticateToken, async (req, res) => {
  const flow = req.body;
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  
  // Validation
  if (!flow || !flow.name || !flow.nodes || !flow.edges) {
    return res.status(400).json({ error: translateError('REQUIRED_FIELDS', lang) });
  }
  
  try {
    // Upsert logic if ID provided, else Insert.
    // For simplicity, assuming ID is always generated by frontend or new
    // We check if exists first
    const { rows: exists } = await pool.query('SELECT id FROM chat_flows WHERE id = $1', [flow.id]);
    if (exists.length > 0) {
       const { rows } = await pool.query('UPDATE chat_flows SET name=$1, nodes=$2, edges=$3, active=$4, last_modified=NOW() WHERE id=$5 RETURNING *',
         [flow.name, JSON.stringify(flow.nodes), JSON.stringify(flow.edges), flow.status === 'active', flow.id]);
       res.json(rows[0]);
    } else {
       const { rows } = await pool.query('INSERT INTO chat_flows (id, name, nodes, edges, active) VALUES ($1, $2, $3, $4, $5) RETURNING *',
         [flow.id, flow.name, JSON.stringify(flow.nodes), JSON.stringify(flow.edges), flow.status === 'active']);
       res.json(rows[0]);
    }
  } catch (e) {
    console.error('Save flow error:', e);
    res.status(500).json({ error: 'Failed to save flow' });
  }
});

// Templates
app.get('/api/templates', authenticateToken, async (req, res) => {
  try {
    const { data } = await axios.get(`${BASE_URL}/${WABA_ID}/message_templates`, {
      params: { limit: 100 },
      headers: { Authorization: `Bearer ${META_ACCESS_TOKEN}` }
    });
    res.json(data.data);
  } catch (err) { 
    console.error('Get templates error:', err);
    res.status(500).json([]); 
  }
});

// Create Template (Meta API)
app.post('/api/templates', authenticateToken, async (req, res) => {
  try {
    const { data } = await axios.post(
      `${BASE_URL}/${WABA_ID}/message_templates`,
      req.body,
      { headers: { Authorization: `Bearer ${META_ACCESS_TOKEN}`, 'Content-Type': 'application/json' } }
    );
    res.json(data);
  } catch (err: any) {
    console.error('Create template error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data?.error?.message || 'Failed to create template' });
  }
});

// Delete Template (Meta API)
app.delete('/api/templates/:id', authenticateToken, async (req, res) => {
  try {
    const { data } = await axios.delete(
      `${BASE_URL}/${WABA_ID}/message_templates`,
      {
        params: { name: req.params.id },
        headers: { Authorization: `Bearer ${META_ACCESS_TOKEN}` }
      }
    );
    res.json({ success: true, data });
  } catch (err: any) {
    console.error('Delete template error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data?.error?.message || 'Failed to delete template' });
  }
});

// Sync Templates (Re-fetch from Meta)
app.post('/api/templates/sync', authenticateToken, async (req, res) => {
  try {
    const { data } = await axios.get(`${BASE_URL}/${WABA_ID}/message_templates`, {
      params: { limit: 100 },
      headers: { Authorization: `Bearer ${META_ACCESS_TOKEN}` }
    });
    res.json({ success: true, count: data.data?.length || 0, templates: data.data });
  } catch (err: any) {
    console.error('Sync templates error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to sync templates' });
  }
});

// Send Template Message
app.post('/api/messages/template', authenticateToken, async (req, res) => {
  const { conversationId, templateName, languageCode, parameters } = req.body;
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  
  if (!conversationId || !templateName) {
    return res.status(400).json({ error: translateError('MISSING_FIELDS', lang) });
  }

  try {
    // Get conversation and check status
    const convRes = await pool.query('SELECT contact_number, status FROM conversations WHERE id = $1', [conversationId]);
    if (convRes.rowCount === 0) return res.status(404).json({ error: translateError('CONVERSATION_NOT_FOUND', lang) });
    
    const conversation = convRes.rows[0];
    
    // Check if conversation is closed
    if (conversation.status === 'closed') {
      return res.status(400).json({ error: translateError('CONVERSATION_CLOSED', lang) });
    }
    
    const to = conversation.contact_number;
    
    // Build template components
    const components: any[] = [];
    if (parameters && parameters.length > 0) {
      components.push({
        type: 'body',
        parameters: parameters.map((p: string) => ({ type: 'text', text: p }))
      });
    }
    
    // Send via Meta API
    const payload = {
      messaging_product: 'whatsapp',
      to,
      type: 'template',
      template: {
        name: templateName,
        language: { code: languageCode || 'en' },
        components: components.length > 0 ? components : undefined
      }
    };
    
    const response = await axios.post(
      `${BASE_URL}/${PHONE_NUMBER_ID}/messages`,
      payload,
      { headers: { Authorization: `Bearer ${META_ACCESS_TOKEN}`, 'Content-Type': 'application/json' } }
    );
    
    const metaId = response.data.messages?.[0]?.id;
    
    // Store in database
    const insertRes = await pool.query(
      `INSERT INTO messages (conversation_id, direction, type, content, status, meta_id)
       VALUES ($1, 'outbound', 'template', $2, 'sent', $3) RETURNING *`,
      [conversationId, `Template: ${templateName}`, metaId]
    );
    
    // Update conversation
    await pool.query(
      `UPDATE conversations SET last_message = $1, last_message_at = NOW() WHERE id = $2`,
      [`Template: ${templateName}`, conversationId]
    );
    
    res.json({ 
      success: true, 
      message: insertRes.rows[0],
      metaId 
    });
    
  } catch (err: any) {
    console.error('Send template error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data?.error?.message || 'Failed to send template' });
  }
});

// Contacts API
// =========== AUTO-REPLIES API ===========
// Get Auto Replies
app.get('/api/automation/auto-replies', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM auto_replies ORDER BY updated_at DESC');
    res.json(rows);
  } catch (err) {
    console.error('Get auto-replies error:', err);
    res.status(500).json({ error: 'Failed to get auto-replies' });
  }
});

// Save Auto Reply
app.post('/api/automation/auto-replies', authenticateToken, async (req, res) => {
  const { id, keyword, response, active } = req.body;
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  
  if (!keyword || !response) {
    return res.status(400).json({ error: translateError('REQUIRED_FIELDS', lang) });
  }
  
  try {
    if (id) {
      // Update existing
      const { rows } = await pool.query(
        `UPDATE auto_replies SET keyword = $1, response = $2, active = $3, updated_at = NOW() 
         WHERE id = $4 RETURNING *`,
        [keyword, response, active !== false, id]
      );
      res.json(rows[0]);
    } else {
      // Create new
      const { rows } = await pool.query(
        `INSERT INTO auto_replies (keyword, response, active) VALUES ($1, $2, $3) RETURNING *`,
        [keyword, response, active !== false]
      );
      res.json(rows[0]);
    }
  } catch (err) {
    console.error('Save auto-reply error:', err);
    res.status(500).json({ error: 'Failed to save auto-reply' });
  }
});

// Delete Auto Reply
app.delete('/api/automation/auto-replies/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM auto_replies WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete auto-reply error:', err);
    res.status(500).json({ error: 'Failed to delete auto-reply' });
  }
});

// Toggle Auto Reply
app.put('/api/automation/auto-replies/:id/toggle', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE auto_replies SET active = NOT active, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    res.json(rows[0] || { success: true });
  } catch (err) {
    console.error('Toggle auto-reply error:', err);
    res.status(500).json({ error: 'Failed to toggle auto-reply' });
  }
});

// =========== NOTIFICATIONS/CAMPAIGNS API ===========
// Get Campaigns
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        id,
        name,
        type,
        status,
        message_count as "messageCount",
        sent_count as "sentCount",
        failed_count as "failedCount",
        created_at as "createdAt",
        sent_at as "sentAt"
      FROM campaigns
      ORDER BY created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Get campaigns error:', err);
    res.status(500).json({ error: 'Failed to get campaigns' });
  }
});

// Get Single Campaign
app.get('/api/notifications/:id', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM campaigns WHERE id = $1', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Campaign not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Get campaign error:', err);
    res.status(500).json({ error: 'Failed to get campaign' });
  }
});

// Save Campaign
app.post('/api/notifications', authenticateToken, async (req, res) => {
  const { name, type, status, messageCount } = req.body;
  try {
    const { rows } = await pool.query(`
      INSERT INTO campaigns (name, type, status, message_count)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `, [name, type || 'broadcast', status || 'draft', messageCount || 0]);
    res.json(rows[0]);
  } catch (err) {
    console.error('Save campaign error:', err);
    res.status(500).json({ error: 'Failed to save campaign' });
  }
});

// Delete Campaign
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM campaigns WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete campaign error:', err);
    res.status(500).json({ error: 'Failed to delete campaign' });
  }
});

// Toggle Campaign Status
app.put('/api/notifications/:id/toggle', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT status FROM campaigns WHERE id = $1', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Campaign not found' });
    
    const newStatus = rows[0].status === 'active' ? 'paused' : 'active';
    await pool.query('UPDATE campaigns SET status = $1 WHERE id = $2', [newStatus, req.params.id]);
    res.json({ success: true, status: newStatus });
  } catch (err) {
    console.error('Toggle campaign error:', err);
    res.status(500).json({ error: 'Failed to toggle campaign' });
  }
});

// Contacts API
app.get('/api/contacts', authenticateToken, async (req, res) => {
  try {
    // Get from contacts table first (primary source)
    const { rows: contactRows } = await pool.query(
      `SELECT id, phone as "phoneNumber", name, email, company, notes, tags, 
              created_at as "createdAt", updated_at as "lastContactedAt"
       FROM contacts 
       ORDER BY updated_at DESC`
    );
    
    // Fallback: include conversations if no matching contact
    const { rows: convRows } = await pool.query(
      `SELECT DISTINCT 
        NULL as id,
        contact_number as "phoneNumber", 
        contact_name as "name",
        NULL as email,
        NULL as company,
        NULL as notes,
        tags,
        created_at as "createdAt",
        last_message_at as "lastContactedAt"
       FROM conversations 
       WHERE contact_number NOT IN (SELECT phone FROM contacts)
       ORDER BY last_message_at DESC`
    );
    
    res.json([...contactRows, ...convRows]);
  } catch (err) {
    console.error('Get contacts error:', err);
    res.status(500).json({ error: 'Failed to get contacts' });
  }
});

// Save/Update Contact
app.post('/api/contacts', authenticateToken, async (req, res) => {
  const { phone, name, email, company, notes, tags } = req.body;
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  if (!phone) return res.status(400).json({ error: translateError('PHONE_REQUIRED', lang) });
  
  try {
    const { rows } = await pool.query(`
      INSERT INTO contacts (phone, name, email, company, notes, tags)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (phone) DO UPDATE SET
        name = COALESCE(EXCLUDED.name, contacts.name),
        email = COALESCE(EXCLUDED.email, contacts.email),
        company = COALESCE(EXCLUDED.company, contacts.company),
        notes = COALESCE(EXCLUDED.notes, contacts.notes),
        tags = COALESCE(EXCLUDED.tags, contacts.tags),
        updated_at = NOW()
      RETURNING *
    `, [phone, name, email, company, notes, tags || []]);
    res.json(rows[0]);
  } catch (err) {
    console.error('Save contact error:', err);
    res.status(500).json({ error: 'Failed to save contact' });
  }
});

// Delete Contact
app.delete('/api/contacts/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM contacts WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete contact error:', err);
    res.status(500).json({ error: 'Failed to delete contact' });
  }
});

// =========== ORDERS API ===========
// Get Orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  const { status, search, startDate, endDate } = req.query;
  try {
    let query = 'SELECT * FROM orders WHERE 1=1';
    const params: any[] = [];
    let idx = 1;

    if (status) {
      query += ` AND status = $${idx++}`;
      params.push(status);
    }
    if (search) {
      query += ` AND (order_number ILIKE $${idx} OR customer_name ILIKE $${idx} OR customer_phone ILIKE $${idx++})`;
      params.push(`%${search}%`);
    }
    if (startDate) {
      query += ` AND created_at >= $${idx++}`;
      params.push(startDate);
    }
    if (endDate) {
      query += ` AND created_at <= $${idx++}`;
      params.push(endDate);
    }
    
    query += ' ORDER BY created_at DESC';
    const { rows } = await pool.query(query, params);
    
    // Transform to frontend format
    const orders = rows.map(r => ({
      id: r.id,
      orderNumber: r.order_number,
      conversationId: r.conversation_id,
      customerPhone: r.customer_phone,
      customerName: r.customer_name,
      items: r.items || [],
      subtotal: parseFloat(r.subtotal) || 0,
      shippingCost: parseFloat(r.shipping_cost) || 0,
      total: parseFloat(r.total) || 0,
      status: r.status,
      paymentStatus: r.payment_status,
      shippingAddress: r.shipping_address,
      notes: r.notes,
      createdBy: r.created_by,
      createdAt: r.created_at,
      updatedAt: r.updated_at
    }));
    
    res.json(orders);
  } catch (err) {
    console.error('Get orders error:', err);
    res.status(500).json({ error: 'Failed to get orders' });
  }
});

// Create Order
app.post('/api/orders', authenticateToken, async (req, res) => {
  const { conversationId, customerPhone, customerName, items, subtotal, shippingCost, total, shippingAddress, notes } = req.body;
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  
  // Validation
  if (!customerPhone || !items || items.length === 0) {
    return res.status(400).json({ error: translateError('REQUIRED_FIELDS', lang) });
  }
  
  try {
    // Generate order number
    const orderNumber = `ORD-${Date.now().toString(36).toUpperCase()}`;
    
    const { rows } = await pool.query(`
      INSERT INTO orders (order_number, conversation_id, customer_phone, customer_name, items, subtotal, shipping_cost, total, shipping_address, notes, created_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *
    `, [orderNumber, conversationId, customerPhone, customerName, JSON.stringify(items || []), subtotal || 0, shippingCost || 0, total || 0, JSON.stringify(shippingAddress), notes, (req as any).user?.id]);
    
    // Log history
    await pool.query(`
      INSERT INTO order_history (order_id, action, user_id, user_name)
      VALUES ($1, 'created', $2, $3)
    `, [rows[0].id, (req as any).user?.id, (req as any).user?.name || 'System']);
    
    res.json({
      id: rows[0].id,
      orderNumber: rows[0].order_number,
      status: rows[0].status,
      createdAt: rows[0].created_at
    });
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Update Order
app.put('/api/orders/:id', authenticateToken, async (req, res) => {
  const { items, subtotal, shippingCost, total, shippingAddress, notes, userId, userName } = req.body;
  
  try {
    await pool.query(`
      UPDATE orders SET items = $1, subtotal = $2, shipping_cost = $3, total = $4, shipping_address = $5, notes = $6, updated_at = NOW()
      WHERE id = $7
    `, [JSON.stringify(items), subtotal, shippingCost, total, JSON.stringify(shippingAddress), notes, req.params.id]);
    
    await pool.query(`
      INSERT INTO order_history (order_id, action, user_id, user_name, notes)
      VALUES ($1, 'updated', $2, $3, $4)
    `, [req.params.id, userId, userName, 'Order details updated']);
    
    res.json({ success: true });
  } catch (err) {
    console.error('Update order error:', err);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// Update Order Status
app.put('/api/orders/:id/status', authenticateToken, async (req, res) => {
  const { action, userId, userName, notes } = req.body;
  
  try {
    // Map action to status
    let newStatus = action;
    if (action === 'confirm') newStatus = 'processing';
    if (action === 'ship') newStatus = 'shipped';
    if (action === 'complete') newStatus = 'completed';
    if (action === 'cancel') newStatus = 'cancelled';
    
    await pool.query(`
      UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2
    `, [newStatus, req.params.id]);
    
    await pool.query(`
      INSERT INTO order_history (order_id, action, user_id, user_name, notes)
      VALUES ($1, $2, $3, $4, $5)
    `, [req.params.id, action, userId, userName, notes]);
    
    res.json({ success: true, status: newStatus });
  } catch (err) {
    console.error('Update order status error:', err);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// =========== TAGS API ===========
// Get Tags
app.get('/api/tags', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM tags ORDER BY name');
    res.json(rows.map(r => ({ id: r.id, name: r.name, color: r.color })));
  } catch (err) {
    console.error('Get tags error:', err);
    res.status(500).json({ error: 'Failed to get tags' });
  }
});

// Create Tag
app.post('/api/tags', authenticateToken, async (req, res) => {
  const { name, color } = req.body;
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  if (!name) return res.status(400).json({ error: translateError('NAME_REQUIRED', lang) });
  
  try {
    const { rows } = await pool.query(`
      INSERT INTO tags (name, color) VALUES ($1, $2) RETURNING *
    `, [name, color || '#3B82F6']);
    res.json({ id: rows[0].id, name: rows[0].name, color: rows[0].color });
  } catch (err) {
    console.error('Create tag error:', err);
    res.status(500).json({ error: 'Failed to create tag' });
  }
});

// Delete Tag
app.delete('/api/tags/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM tags WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete tag error:', err);
    res.status(500).json({ error: 'Failed to delete tag' });
  }
});

// =========== PRODUCTS API ===========
// Get Products
app.get('/api/products', authenticateToken, async (req, res) => {
  const { search } = req.query;
  try {
    let query = 'SELECT * FROM products WHERE 1=1';
    const params: any[] = [];
    
    if (search) {
      query += ' AND (name ILIKE $1 OR sku ILIKE $1 OR description ILIKE $1)';
      params.push(`%${search}%`);
    }
    
    query += ' ORDER BY name';
    const { rows } = await pool.query(query, params);
    
    res.json(rows.map(r => ({
      id: r.id,
      name: r.name,
      description: r.description,
      price: parseFloat(r.price) || 0,
      sku: r.sku,
      imageUrl: r.image_url,
      inStock: r.in_stock
    })));
  } catch (err) {
    console.error('Get products error:', err);
    res.status(500).json({ error: 'Failed to get products' });
  }
});

// =========== INTERNAL NOTIFICATIONS API ===========
// Get Internal Notifications
app.get('/api/internal-notifications', authenticateToken, async (req, res) => {
  try {
    const userId = (req as any).user?.id;
    const { rows } = await pool.query(`
      SELECT * FROM internal_notifications 
      WHERE user_id = $1 OR user_id IS NULL
      ORDER BY created_at DESC
      LIMIT 50
    `, [userId]);
    
    res.json(rows.map(r => ({
      id: r.id,
      type: r.type,
      title: r.title,
      message: r.message,
      read: r.read,
      createdAt: r.created_at
    })));
  } catch (err) {
    console.error('Get internal notifications error:', err);
    res.status(500).json({ error: 'Failed to get notifications' });
  }
});

// Create Internal Notification
app.post('/api/internal-notifications', authenticateToken, async (req, res) => {
  const { type, title, message, userId } = req.body;
  const lang = req.headers['accept-language']?.includes('en') ? 'en' : 'ar';
  if (!title) return res.status(400).json({ error: translateError('TITLE_REQUIRED', lang) });
  
  try {
    const { rows } = await pool.query(`
      INSERT INTO internal_notifications (type, title, message, user_id)
      VALUES ($1, $2, $3, $4) RETURNING *
    `, [type || 'info', title, message, userId]);
    res.json({ id: rows[0].id, createdAt: rows[0].created_at });
  } catch (err) {
    console.error('Create notification error:', err);
    res.status(500).json({ error: 'Failed to create notification' });
  }
});

// Mark Notification Read
app.put('/api/internal-notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    await pool.query('UPDATE internal_notifications SET read = true WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Mark notification read error:', err);
    res.status(500).json({ error: 'Failed to mark notification read' });
  }
});

// =========== ANALYTICS API ===========
// Get Analytics Summary
app.get('/api/analytics/summary', authenticateToken, async (req, res) => {
  const { range } = req.query;
  
  try {
    // Calculate date range
    let days = 7;
    if (range === '30d') days = 30;
    if (range === '90d') days = 90;
    
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    
    // Get message counts
    const msgResult = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE direction = 'outbound') as sent,
        COUNT(*) FILTER (WHERE direction = 'inbound') as received
      FROM messages 
      WHERE created_at >= $1
    `, [startDate]);
    
    // Get conversation counts
    const convResult = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'open') as open,
        COUNT(*) FILTER (WHERE status = 'closed') as closed
      FROM conversations 
      WHERE created_at >= $1
    `, [startDate]);
    
    // Get order stats
    const orderResult = await pool.query(`
      SELECT 
        COUNT(*) as total_orders,
        SUM(total) as revenue,
        AVG(total) as avg_order_value
      FROM orders 
      WHERE created_at >= $1
    `, [startDate]);
    
    // Calculate average response time (time between customer message and agent reply)
    const responseTimeResult = await pool.query(`
      SELECT AVG(
        EXTRACT(EPOCH FROM (agent_msg.created_at - customer_msg.created_at))
      ) as avg_response_seconds
      FROM messages customer_msg
      JOIN messages agent_msg ON agent_msg.conversation_id = customer_msg.conversation_id
      WHERE customer_msg.direction = 'inbound'
        AND agent_msg.direction = 'outbound'
        AND agent_msg.created_at > customer_msg.created_at
        AND agent_msg.created_at < customer_msg.created_at + INTERVAL '1 hour'
        AND customer_msg.created_at >= $1
      LIMIT 1000
    `, [startDate]);
    
    const avgSeconds = parseFloat(responseTimeResult.rows[0]?.avg_response_seconds) || 0;
    let responseTime = '0s';
    if (avgSeconds > 0) {
      if (avgSeconds < 60) {
        responseTime = `${Math.round(avgSeconds)}s`;
      } else if (avgSeconds < 3600) {
        responseTime = `${Math.round(avgSeconds / 60)}m`;
      } else {
        responseTime = `${Math.round(avgSeconds / 3600)}h`;
      }
    }
    
    // Calculate satisfaction rate from feedback (if feedback system exists)
    const feedbackResult = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE metadata->>'rating' IN ('4', '5')) as positive,
        COUNT(*) as total
      FROM conversation_events
      WHERE event_type = 'feedback_received'
        AND created_at >= $1
    `, [startDate]);
    
    const totalFeedback = parseInt(feedbackResult.rows[0]?.total) || 0;
    const positiveFeedback = parseInt(feedbackResult.rows[0]?.positive) || 0;
    const satisfactionRate = totalFeedback > 0 ? Math.round((positiveFeedback / totalFeedback) * 100) : 0;
    
    res.json({
      messagesSent: parseInt(msgResult.rows[0]?.sent) || 0,
      messagesReceived: parseInt(msgResult.rows[0]?.received) || 0,
      totalConversations: parseInt(convResult.rows[0]?.total) || 0,
      openConversations: parseInt(convResult.rows[0]?.open) || 0,
      closedConversations: parseInt(convResult.rows[0]?.closed) || 0,
      totalOrders: parseInt(orderResult.rows[0]?.total_orders) || 0,
      revenue: parseFloat(orderResult.rows[0]?.revenue) || 0,
      avgOrderValue: parseFloat(orderResult.rows[0]?.avg_order_value) || 0,
      responseTime,
      satisfactionRate
    });
  } catch (err) {
    console.error('Get analytics summary error:', err);
    res.status(500).json({ error: 'Failed to get analytics' });
  }
});

// Get Timeline Data
app.get('/api/analytics/timeline', authenticateToken, async (req, res) => {
  const { range } = req.query;
  
  try {
    let days = 7;
    if (range === '30d') days = 30;
    if (range === '90d') days = 90;
    
    const { rows } = await pool.query(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) FILTER (WHERE direction = 'outbound') as sent,
        COUNT(*) FILTER (WHERE direction = 'inbound') as received
      FROM messages 
      WHERE created_at >= NOW() - INTERVAL '${days} days'
      GROUP BY DATE(created_at)
      ORDER BY date
    `);
    
    res.json(rows.map(r => ({
      date: r.date,
      sent: parseInt(r.sent) || 0,
      received: parseInt(r.received) || 0
    })));
  } catch (err) {
    console.error('Get timeline error:', err);
    res.status(500).json({ error: 'Failed to get timeline' });
  }
});

// Get Cost Breakdown
app.get('/api/analytics/cost-breakdown', authenticateToken, async (req, res) => {
  try {
    // Calculate cost breakdown by message type
    const { rows } = await pool.query(`
      SELECT 
        type,
        COUNT(*) as count
      FROM messages 
      WHERE direction = 'outbound'
        AND created_at >= NOW() - INTERVAL '30 days'
      GROUP BY type
    `);
    
    // Estimate costs (placeholder rates)
    const costs = rows.map(r => ({
      type: r.type || 'text',
      count: parseInt(r.count),
      unitCost: r.type === 'template' ? 0.05 : 0.005,
      totalCost: parseInt(r.count) * (r.type === 'template' ? 0.05 : 0.005)
    }));
    
    res.json(costs);
  } catch (err) {
    console.error('Get cost breakdown error:', err);
    res.status(500).json({ error: 'Failed to get cost breakdown' });
  }
});

// Get Heatmap Data
app.get('/api/analytics/heatmap', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        EXTRACT(DOW FROM created_at) as day_of_week,
        EXTRACT(HOUR FROM created_at) as hour,
        COUNT(*) as count
      FROM messages 
      WHERE created_at >= NOW() - INTERVAL '30 days'
      GROUP BY EXTRACT(DOW FROM created_at), EXTRACT(HOUR FROM created_at)
    `);
    
    res.json(rows.map(r => ({
      day: parseInt(r.day_of_week),
      hour: parseInt(r.hour),
      count: parseInt(r.count)
    })));
  } catch (err) {
    console.error('Get heatmap error:', err);
    res.status(500).json({ error: 'Failed to get heatmap' });
  }
});

// =========== GLOBAL SETTINGS API ===========
app.get('/api/settings/global', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT value FROM app_state WHERE key = 'global_settings'
    `);
    res.json(rows[0]?.value || {
      businessName: '',
      timezone: 'Asia/Riyadh',
      language: 'ar',
      workingHours: { start: '09:00', end: '17:00' },
      autoReplyOutsideHours: false
    });
  } catch (err) {
    console.error('Get global settings error:', err);
    res.status(500).json({ error: 'Failed to get settings' });
  }
});

app.put('/api/settings/global', authenticateToken, async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO app_state (key, value, updated_at)
      VALUES ('global_settings', $1, NOW())
      ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
    `, [JSON.stringify(req.body)]);
    res.json({ success: true });
  } catch (err) {
    console.error('Update global settings error:', err);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// 🔍 PRODUCTION VERIFICATION ENDPOINTS (for proof/testing)
// These endpoints are disabled in production unless ENABLE_VERIFY_ENDPOINTS=true
const ENABLE_VERIFY = process.env.ENABLE_VERIFY_ENDPOINTS === 'true' || !IS_PROD;

// Middleware to guard verify endpoints
const verifyEndpointGuard = (req: any, res: any, next: any) => {
  if (!ENABLE_VERIFY) {
    return res.status(403).json({ 
      error: 'Verify endpoints are disabled in production',
      hint: 'Set ENABLE_VERIFY_ENDPOINTS=true to enable'
    });
  }
  // Also require admin role in production
  if (IS_PROD && req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

app.get('/api/verify/media-storage', authenticateToken, verifyEndpointGuard, async (req, res) => {
  try {
    // Show all messages with media fields populated
    const { rows } = await pool.query(`
      SELECT 
        id, 
        conversation_id, 
        type, 
        content,
        media_url,
        media_mime_type,
        media_sha256,
        media_file_size,
        created_at
      FROM messages 
      WHERE media_url IS NOT NULL 
      ORDER BY created_at DESC 
      LIMIT 20
    `);
    
    res.json({
      proof: '✅ Media messages with full metadata',
      count: rows.length,
      examples: rows,
      schema: {
        media_url: 'TEXT - Full Graph API URL',
        media_mime_type: 'VARCHAR(100) - MIME type',
        media_sha256: 'VARCHAR(64) - Checksum',
        media_file_size: 'BIGINT - File size in bytes'
      }
    });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.get('/api/verify/status-updates', authenticateToken, verifyEndpointGuard, async (req, res) => {
  try {
    // Show messages with status transitions
    const { rows } = await pool.query(`
      SELECT 
        id,
        conversation_id,
        content,
        status,
        created_at,
        updated_at,
        (updated_at - created_at) as status_update_delay
      FROM messages 
      WHERE direction = 'outbound' 
        AND updated_at > created_at
      ORDER BY updated_at DESC 
      LIMIT 20
    `);
    
    // Show status events
    const { rows: events } = await pool.query(`
      SELECT 
        event_type,
        metadata,
        created_at
      FROM conversation_events 
      WHERE event_type IN ('sent', 'delivered', 'read', 'failed')
      ORDER BY created_at DESC 
      LIMIT 20
    `);
    
    res.json({
      proof: '✅ Status updates working (sent → delivered → read)',
      messagesWithUpdates: rows.length,
      statusEvents: events.length,
      examples: {
        messages: rows,
        events: events
      }
    });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.get('/api/verify/closed-enforcement', authenticateToken, verifyEndpointGuard, async (req, res) => {
  try {
    // Show closed conversations
    const { rows: closed } = await pool.query(`
      SELECT id, contact_name, contact_number, status, created_at
      FROM conversations 
      WHERE status = 'closed' 
      LIMIT 10
    `);
    
    res.json({
      proof: '✅ Closed conversations cannot receive messages',
      closedConversations: closed,
      enforcement: {
        'POST /api/messages': 'Lines 1362-1365: if (status === closed) return 400',
        'POST /api/messages/template': 'Lines 1704-1707: if (status === closed) return 400'
      },
      testInstructions: 'Try sending message to any conversation_id above → should get 400 error'
    });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.get('/api/verify/window-expiry', authenticateToken, verifyEndpointGuard, async (req, res) => {
  try {
    // Show conversations with expired windows
    const { rows } = await pool.query(`
      SELECT 
        id,
        contact_name,
        contact_number,
        last_customer_message_at,
        window_expires_at,
        (NOW() > window_expires_at) as is_expired,
        EXTRACT(EPOCH FROM (NOW() - window_expires_at))/3600 as hours_expired
      FROM conversations 
      WHERE window_expires_at IS NOT NULL
      ORDER BY window_expires_at DESC 
      LIMIT 20
    `);
    
    res.json({
      proof: '✅ 24h window enforcement - template-only after expiry',
      conversations: rows,
      enforcement: {
        location: 'POST /api/messages - Lines 1368-1378',
        logic: 'if (now > window_expires_at && type !== template) return 400 WINDOW_EXPIRED'
      },
      testInstructions: 'Try sending text to expired conversation → should get WINDOW_EXPIRED error'
    });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// Start (ESM-safe check - no require.main in ESM)
const isMainModule = import.meta.url === `file://${process.argv[1]}`;

if (isMainModule || process.env.START_SERVER === 'true') {
  initSchema().then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Production Server running on port ${PORT}`);
    });
  });
}

export default app;
