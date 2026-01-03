import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function resetPassword(email: string, newPassword: string) {
  try {
    // Check if user exists
    const { rows } = await pool.query('SELECT id, name FROM users WHERE email = $1', [email]);
    
    if (rows.length === 0) {
      console.log('❌ User not found:', email);
      return;
    }

    const user = rows[0];
    console.log('✅ Found user:', user.name, `(${email})`);

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update the password
    await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [hashedPassword, email]);
    
    console.log('✅ Password updated successfully!');
    console.log('📧 Email:', email);
    console.log('🔑 New password:', newPassword);
    
  } catch (err) {
    console.error('❌ Error:', err);
  } finally {
    await pool.end();
  }
}

// Get email and password from command line arguments
const email = process.argv[2];
const password = process.argv[3];

if (!email || !password) {
  console.log('Usage: npx ts-node reset-password.ts <email> <password>');
  console.log('Example: npx ts-node reset-password.ts info@guthmi.com newPassword123');
  process.exit(1);
}

resetPassword(email, password);
