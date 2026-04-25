import { startServer } from './src/server.js';
import { initDb } from './src/db.js';
import dotenv from 'dotenv';
import { resolve } from 'path';

dotenv.config();

import { networkInterfaces } from 'os';

const PORT = process.env.PORT || 8080;
const HOST = '0.0.0.0'; 

function getLocalIP() {
  const nets = networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) return net.address;
    }
  }
  return 'YOUR_IP_ADDRESS';
}

async function start() {
  console.log('🚀 Starting TeleVault Web Server...');
  
  try {
    await initDb();
    startServer(PORT, HOST);
    
    const localIP = getLocalIP();
    console.log('\n================================================');
    console.log(`✅ TeleVault is now LIVE!`);
    console.log(`🏠 Local access:  http://localhost:${PORT}`);
    console.log(`🌐 Network access: http://${localIP}:${PORT}`);
    console.log('================================================\n');
    
  } catch (err) {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  }
}

start();
