const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DB_FILE = path.join(__dirname, 'portal_db.json');
const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';

// Load or initialize database
function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ devices: {} }, null, 2));
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (_) {
    return { devices: {} };
  }
}

function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Exact IBO Player Pro DataEncodeRepository cipher (customEncode / customDecode)
function customEncode(obj) {
  const jsonStr = typeof obj === 'string' ? obj : JSON.stringify(obj);
  const encoded = Buffer.from(jsonStr, 'utf8').toString('base64');
  const pos = Math.floor(Math.random() * 21) + 1; // 1..21
  const len = Math.floor(Math.random() * 31);     // 0..30
  let pad = '';
  for (let i = 0; i < len; i++) {
    pad += ALPHABET[Math.floor(Math.random() * 62)];
  }
  return encoded.slice(0, pos) + pad + encoded.slice(pos) + ALPHABET[pos] + ALPHABET[len];
}

function customDecode(payload) {
  const pos = ALPHABET.indexOf(payload[payload.length - 2]);
  const len = ALPHABET.indexOf(payload[payload.length - 1]);
  const body = payload.slice(0, payload.length - 2);
  const cleanB64 = body.slice(0, pos) + body.slice(pos + len);
  return JSON.parse(Buffer.from(cleanB64, 'base64').toString('utf8'));
}

// Convert raw app_device_id into deterministic MAC address + 6-digit device_key
function getOrCreateDevice(db, rawId, explicitMac) {
  let mac = explicitMac;
  if (!mac) {
    const hash = crypto.createHash('md5').update(rawId || 'default').digest('hex');
    mac = hash.match(/.{1,2}/g).slice(0, 6).join(':');
  }
  mac = mac.toLowerCase();
  if (!db.devices[mac]) {
    const deviceKey = String(Math.floor(100000 + Math.random() * 900000));
    db.devices[mac] = {
      mac_address: mac,
      device_key: deviceKey,
      is_trial: 0, // 0 = Activated (Unlimited)
      expire_date: '2099-12-31',
      playlists: [],
      deleted_ids: []
    };
    saveDb(db);
  }
  // Ensure array structure
  if (!Array.isArray(db.devices[mac].playlists)) {
    db.devices[mac].playlists = [];
  } else {
    db.devices[mac].playlists = db.devices[mac].playlists.filter(p => p && p.url && p.url.trim().length > 0);
  }
  if (!Array.isArray(db.devices[mac].deleted_ids)) {
    db.devices[mac].deleted_ids = [];
  }
  return db.devices[mac];
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  // Serve Logo & Favicon
  if (req.method === 'GET' && (req.url === '/logo.png' || req.url === '/favicon.ico')) {
    const logoPath = path.join(__dirname, 'logo.png');
    if (fs.existsSync(logoPath)) {
      res.writeHead(200, {
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=86400'
      });
      return fs.createReadStream(logoPath).pipe(res);
    }
  }

  // Serve Web UI at GET /
  if (req.method === 'GET' && (req.url === '/' || req.url.startsWith('/?'))) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(WEB_UI_HTML);
  }

  // Parse POST body
  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body || '{}');
        // Support both IBO encrypted {"data": "..."} and plain JSON from Web UI
        const payload = parsed.data ? customDecode(parsed.data) : parsed;
        const db = loadDb();

        // 1. App Startup Handshake: POST /authenticate
        if (req.url === '/authenticate' || req.url === '/desktopRequest/authenticate') {
          const dev = getOrCreateDevice(db, payload.app_device_id, payload.mac_address);

          if (payload.device_key && !dev.device_key) {
            dev.device_key = payload.device_key;
          }

          // If app sent local_playlists, only merge items that have NOT been deleted!
          if (Array.isArray(payload.local_playlists) && payload.local_playlists.length > 0) {
            for (const lp of payload.local_playlists) {
              const lId = lp.id;
              // Never resurrect a playlist that was explicitly deleted!
              if (lId && dev.deleted_ids.includes(lId)) {
                continue;
              }
              const lUrl = (lp.url || lp.playlist_url || '').trim();
              if (!lUrl) continue;
              const lName = (lp.title || lp.name || lp.playlist_name || 'My Playlist').trim();
              const existsIdx = dev.playlists.findIndex(p => p.id === lId || p.url === lUrl);
              const entry = {
                id: lId || crypto.randomBytes(12).toString('hex'),
                name: lName,
                playlist_name: lName,
                url: lUrl,
                type: lp.type || 'general',
                is_protected: (lp.is_protected == 1 || lp.isProtected === true) ? 1 : 0
              };
              if (existsIdx >= 0) {
                dev.playlists[existsIdx] = entry;
              } else {
                dev.playlists.push(entry);
              }
            }
            saveDb(db);
          }

          const responseObj = {
            status: 'success',
            mac_address: dev.mac_address,
            device_key: dev.device_key,
            is_trial: dev.is_trial,
            expire_date: dev.expire_date,
            urls: dev.playlists,
            deleted_ids: dev.deleted_ids,
            languages: []
          };
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ data: customEncode(responseObj), plain: responseObj }));
        }

        // 2. Web UI Login: POST /web/login
        if (req.url === '/web/login') {
          const mac = (payload.mac_address || '').trim().toLowerCase();
          const key = (payload.device_key || '').trim();
          const dev = db.devices[mac];
          if (!dev || dev.device_key !== key) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Invalid MAC Address or Device Key' }));
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify(dev));
        }

        // 3. Add or Edit Playlist: POST /playlists
        if (req.url === '/playlists' || req.url === '/desktopRequest/playlists') {
          const dev = getOrCreateDevice(db, payload.app_device_id, payload.mac_address);
          if (payload.web_auth && payload.device_key !== dev.device_key) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Unauthorized Device Key' }));
          }

          const pid = (payload.playlist_id && payload.playlist_id !== '-1')
            ? payload.playlist_id
            : crypto.randomBytes(12).toString('hex');
          const pName = (payload.playlist_name || payload.name || 'New Playlist').trim();
          const pUrl = (payload.playlist_url || payload.url || '').trim();
          const pType = payload.playlist_type || payload.type || 'general';
          const pProt = (payload.is_protected == 1 || payload.isProtected === true) ? 1 : 0;

          // If updating or resurrecting, remove from deleted_ids
          if (Array.isArray(dev.deleted_ids)) {
            dev.deleted_ids = dev.deleted_ids.filter(id => id !== pid);
          }

          const entry = {
            id: pid,
            name: pName,
            playlist_name: pName,
            url: pUrl,
            type: pType,
            is_protected: pProt
          };

          const idx = dev.playlists.findIndex(p => p.id === pid || p.url === pUrl);
          if (idx >= 0) {
            dev.playlists[idx] = entry;
          } else {
            dev.playlists.push(entry);
          }
          saveDb(db);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ data: customEncode(entry), plain: entry, playlists: dev.playlists }));
        }

        // 4. Delete Playlist: POST /playlists/delete
        if (req.url === '/playlists/delete' || req.url === '/desktopRequest/playlists/delete') {
          const dev = getOrCreateDevice(db, payload.app_device_id, payload.mac_address);
          if (payload.web_auth && payload.device_key !== dev.device_key) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Unauthorized Device Key' }));
          }

          // Register tombstone in deleted_ids so it is NEVER resurrected by any client
          if (!Array.isArray(dev.deleted_ids)) dev.deleted_ids = [];
          if (payload.playlist_id && !dev.deleted_ids.includes(payload.playlist_id)) {
            dev.deleted_ids.push(payload.playlist_id);
          }

          dev.playlists = dev.playlists.filter(p => p.id !== payload.playlist_id);
          saveDb(db);
          const resp = { status: 'success' };
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ data: customEncode(resp), plain: resp, playlists: dev.playlists }));
        }
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: e.message }));
      }
    });
  }
});

const WEB_UI_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <link rel="icon" type="image/png" href="/logo.png" />
  <meta name="theme-color" content="#12111A" />
  <title>Stayk4_ Player — Web Playlist Manager</title>
  <style>
    * { box-sizing: border-box; }
    body {
      background: #12111A;
      color: #FFFFFF;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 32px 16px;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .card {
      width: 100%;
      background: #1E1C28;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 28px;
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.55);
      position: relative;
    }
    #loginCard {
      max-width: 550px;
      padding: 40px 38px;
    }
    #managerCard {
      max-width: 880px;
      padding: 36px 36px;
    }
    .brand-header {
      display: flex;
      align-items: center;
      gap: 14px;
      margin-bottom: 6px;
    }
    .brand-logo {
      width: 50px;
      height: 50px;
      border-radius: 14px;
      box-shadow: 0 6px 20px rgba(139, 92, 246, 0.45);
      object-fit: cover;
      flex-shrink: 0;
    }
    .brand-title {
      margin: 0;
      font-size: 21px;
      font-weight: 700;
      color: #FFFFFF;
      letter-spacing: -0.2px;
    }
    .brand-subtitle {
      color: #9CA3AF;
      line-height: 1.55;
      font-size: 13.5px;
      margin: 16px 0 24px 0;
    }
    .form-label {
      display: block;
      font-weight: 600;
      font-size: 13px;
      color: #E5E7EB;
      margin-bottom: 8px;
    }
    input, select {
      width: 100%;
      padding: 13px 18px;
      margin-bottom: 18px;
      border-radius: 14px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      background: #15141D;
      color: #FFFFFF;
      font-size: 14px;
      transition: all 0.2s ease;
    }
    .mono-input {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      letter-spacing: 0.5px;
    }
    input:focus, select:focus {
      border-color: #8B5CF6;
      outline: none;
      box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.25);
    }
    button.btn-primary {
      background: linear-gradient(135deg, #8B5CF6 0%, #A855F7 100%);
      color: #FFFFFF;
      border: none;
      padding: 13px 28px;
      border-radius: 14px;
      font-weight: 700;
      cursor: pointer;
      font-size: 14px;
      box-shadow: 0 8px 24px rgba(139, 92, 246, 0.4);
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    button.btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 28px rgba(139, 92, 246, 0.55);
    }
    button.btn-secondary {
      background: #2B2838;
      color: #E5E7EB;
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 8px 16px;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      font-size: 12.5px;
      transition: all 0.2s;
    }
    button.btn-secondary:hover {
      background: #363246;
      color: #FFFFFF;
    }
    button.btn-danger {
      background: rgba(239, 68, 68, 0.15);
      color: #EF4444;
      border: 1px solid rgba(239, 68, 68, 0.25);
      padding: 8px 16px;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      font-size: 12.5px;
      transition: all 0.2s;
    }
    button.btn-danger:hover {
      background: rgba(239, 68, 68, 0.28);
    }
    .playlist-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #15141D;
      padding: 16px 20px;
      border-radius: 14px;
      margin-bottom: 12px;
      border: 1px solid rgba(255, 255, 255, 0.06);
      transition: all 0.2s;
    }
    .playlist-row:hover {
      border-color: rgba(139, 92, 246, 0.45);
      background: #181622;
    }
    .tabs {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
    }
    .tab {
      flex: 1;
      text-align: center;
      padding: 12px;
      background: #15141D;
      border-radius: 12px;
      cursor: pointer;
      border: 1px solid rgba(255, 255, 255, 0.08);
      font-size: 14px;
      font-weight: 600;
      color: #9CA3AF;
      transition: all 0.2s;
    }
    .tab.active {
      border-color: #8B5CF6;
      color: #FFFFFF;
      font-weight: 700;
      background: #2B2838;
      box-shadow: 0 0 16px rgba(139, 92, 246, 0.25);
    }
    .status-badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 800;
      background: rgba(16, 185, 129, 0.15);
      color: #10B981;
      border: 1px solid rgba(16, 185, 129, 0.3);
      margin-left: 10px;
      letter-spacing: 0.5px;
    }
    .sync-indicator {
      font-size: 12px;
      color: #10B981;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      margin-top: 4px;
    }
    .sync-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #10B981;
      display: inline-block;
      box-shadow: 0 0 8px #10B981;
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }
  </style>
</head>
<body>
  <!-- Login Screen Card -->
  <div class="card" id="loginCard">
    <div class="brand-header">
      <img src="/logo.png" alt="Stayk4_ Player" class="brand-logo" />
      <div>
        <h1 class="brand-title">Stayk4_ Player</h1>
        <div style="color: #A78BFA; font-size: 13px; font-weight: 600; letter-spacing: 0.3px;">Web Playlist Manager</div>
      </div>
    </div>

    <p class="brand-subtitle">Enter the <b>MAC Address</b> and <b>Device Key</b> shown on your TV or app screen. Your login will be securely remembered on this device:</p>

    <label class="form-label">MAC Address</label>
    <input id="macInput" class="mono-input" placeholder="e.g. cc:a4:7a:b8:9a:5d" />

    <label class="form-label" style="margin-top: 4px;">Device Key (6 digits)</label>
    <input id="keyInput" class="mono-input" placeholder="e.g. 970038" />

    <button class="btn-primary" onclick="login()" style="margin-top: 6px;">Login to Device</button>
  </div>

  <!-- Manager Screen Card -->
  <div class="card" id="managerCard" style="display:none;">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 24px; padding-bottom: 18px; border-bottom: 1px solid rgba(255, 255, 255, 0.06);">
      <div style="display:flex; align-items:center; gap: 14px;">
        <img src="/logo.png" alt="Stayk4_ Player" class="brand-logo" style="width: 44px; height: 44px; border-radius: 12px;" />
        <div>
          <div style="display:flex; align-items:center; gap: 8px;">
            <h2 style="margin: 0; font-size: 19px; font-weight: 700; color: #FFFFFF;">Device: <span id="macLabel" style="color: #C4B5FD; font-family: ui-monospace, monospace;"></span></h2>
            <span class="status-badge">ACTIVATED • LIFETIME</span>
          </div>
          <div class="sync-indicator"><span class="sync-dot"></span> Live Sync Connected with Stayk4_ Player</div>
        </div>
      </div>
      <div style="display:flex; gap:10px;">
        <button class="btn-secondary" onclick="fetchLivePlaylists(true)">↻ Refresh</button>
        <button class="btn-secondary" onclick="logout()" style="color: #EF4444; border-color: rgba(239, 68, 68, 0.25);">Logout</button>
      </div>
    </div>

    <h3 style="margin-top: 20px; margin-bottom: 14px; font-size: 16px; font-weight: 700; color: #FFFFFF;">Connected Playlists</h3>
    <div id="playlistList"></div>

    <hr style="border: none; border-top: 1px solid rgba(255, 255, 255, 0.06); margin: 26px 0;" />

    <h3 style="font-size: 18px; font-weight: 700; color: #FFFFFF; margin-bottom: 16px;" id="formTitle">Add New Playlist</h3>
    <div class="tabs">
      <div class="tab active" id="tabM3u" onclick="setMode('m3u')">Add M3U URL</div>
      <div class="tab" id="tabXc" onclick="setMode('xc')">Xtream Codes API</div>
    </div>

    <label class="form-label">Playlist Name</label>
    <input id="pName" placeholder="My IPTV" />

    <div id="m3uFields">
      <label class="form-label">M3U / M3U8 URL</label>
      <input id="pUrl" class="mono-input" placeholder="http://server:port/get.php?username=...&password=...&type=m3u_plus" />
    </div>

    <div id="xcFields" style="display:none;">
      <label class="form-label">Server URL / Host</label>
      <input id="xcHost" class="mono-input" placeholder="http://example.com:8080" />
      <label class="form-label">Username</label>
      <input id="xcUser" placeholder="Username" />
      <label class="form-label">Password</label>
      <input id="xcPass" type="password" placeholder="Password" />
    </div>

    <label style="display:flex; align-items:center; gap:10px; cursor:pointer; margin-bottom: 22px; color: #E5E7EB; font-size: 13.5px;">
      <input type="checkbox" id="pProtected" style="width:16px; height:16px; margin:0; accent-color: #8B5CF6;" /> Protect Playlist (Hide URL & lock editing in app)
    </label>

    <button id="saveBtn" class="btn-primary" onclick="savePlaylist()">Save Playlist</button>
  </div>

  <script>
    let currentMac = '', currentKey = '', mode = 'm3u', editingId = null;

    // Session Persistence
    window.addEventListener('DOMContentLoaded', () => {
      const params = new URLSearchParams(location.search);
      let mac = (params.get('mac') || '').trim();
      let key = (params.get('key') || '').trim();

      if (!mac) mac = localStorage.getItem('stayk4_portal_mac') || localStorage.getItem('ibo_portal_mac') || '';
      if (!key) key = localStorage.getItem('stayk4_portal_key') || localStorage.getItem('ibo_portal_key') || '';

      if (mac) document.getElementById('macInput').value = mac;
      if (key) document.getElementById('keyInput').value = key;

      if (mac && key) {
        login(mac, key);
      }
    });

    function setMode(m) {
      mode = m;
      document.getElementById('tabM3u').className = m === 'm3u' ? 'tab active' : 'tab';
      document.getElementById('tabXc').className = m === 'xc' ? 'tab active' : 'tab';
      document.getElementById('m3uFields').style.display = m === 'm3u' ? 'block' : 'none';
      document.getElementById('xcFields').style.display = m === 'xc' ? 'block' : 'none';
    }

    async function login(explicitMac, explicitKey) {
      currentMac = (explicitMac || document.getElementById('macInput').value).trim().toLowerCase();
      currentKey = (explicitKey || document.getElementById('keyInput').value).trim();
      if (!currentMac || !currentKey) return alert('Please enter both MAC Address and Device Key');

      try {
        const res = await fetch('/web/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mac_address: currentMac, device_key: currentKey })
        });
        if (!res.ok) {
          localStorage.removeItem('stayk4_portal_mac');
          localStorage.removeItem('stayk4_portal_key');
          return alert('Invalid MAC Address or Device Key!');
        }

        localStorage.setItem('stayk4_portal_mac', currentMac);
        localStorage.setItem('stayk4_portal_key', currentKey);

        const dev = await res.json();
        document.getElementById('loginCard').style.display = 'none';
        document.getElementById('managerCard').style.display = 'block';
        document.getElementById('macLabel').textContent = dev.mac_address;
        renderPlaylists(dev.playlists);
      } catch (err) {
        alert('Could not connect to portal server: ' + err.message);
      }
    }

    function logout() {
      localStorage.removeItem('stayk4_portal_mac');
      localStorage.removeItem('stayk4_portal_key');
      currentMac = '';
      currentKey = '';
      document.getElementById('managerCard').style.display = 'none';
      document.getElementById('loginCard').style.display = 'block';
      document.getElementById('macInput').value = '';
      document.getElementById('keyInput').value = '';
    }

    async function fetchLivePlaylists(notifySuccess) {
      if (!currentMac || !currentKey) return;
      try {
        const res = await fetch('/web/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mac_address: currentMac, device_key: currentKey })
        });
        if (res.ok) {
          const dev = await res.json();
          renderPlaylists(dev.playlists);
          if (notifySuccess) alert('Playlists updated successfully!');
        }
      } catch (_) {}
    }

    // Live sync polling every 3 seconds: automatically updates web UI when app adds/deletes playlists
    setInterval(() => {
      if (document.getElementById('managerCard').style.display === 'block') {
        fetchLivePlaylists(false);
      }
    }, 3000);

    function renderPlaylists(list) {
      const container = document.getElementById('playlistList');
      if (!list || !list.length) {
        container.innerHTML = '<p style="color:#9CA3AF; padding: 14px 0; font-size: 13.5px;">No playlists added yet. Add your M3U or Xtream Codes playlist below!</p>';
        return;
      }
      container.innerHTML = list.map(p => \`
        <div class="playlist-row">
          <div style="flex:1; margin-right: 16px;">
            <div style="display:flex; align-items:center; gap:10px;">
              <strong style="font-size:15px; color:#FFFFFF; font-weight:700;">\${p.name || p.playlist_name}</strong>
              <span style="font-size:11px; padding:3px 8px; border-radius:6px; background:\${p.type === 'xc' ? 'rgba(168, 85, 247, 0.25)' : 'rgba(139, 92, 246, 0.25)'}; color:#C4B5FD; font-weight:700; border:1px solid rgba(168, 85, 247, 0.35);">\${p.type === 'xc' ? 'Xtream API' : 'M3U'}</span>
              \${p.is_protected ? '<span style="font-size:11.5px; padding:2px 8px; border-radius:6px; background:rgba(245, 158, 11, 0.15); color:#FBBF24; font-weight:600;">🔒 Protected</span>' : ''}
            </div>
            <div style="color:#9CA3AF; font-size:12px; margin-top:6px; word-break:break-all; font-family: ui-monospace, monospace;">\${p.is_protected ? 'Protected URL' : p.url}</div>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="btn-secondary" onclick='startEdit(\${JSON.stringify(p).replace(/'/g, "&#39;")})'>Edit</button>
            <button class="btn-danger" onclick="deletePlaylist('\${p.id}')">Delete</button>
          </div>
        </div>
      \`).join('');
    }

    function startEdit(p) {
      editingId = p.id;
      document.getElementById('formTitle').textContent = 'Edit Playlist: ' + (p.name || p.playlist_name);
      document.getElementById('saveBtn').textContent = 'Save Changes';
      document.getElementById('pName').value = p.name || p.playlist_name || '';
      document.getElementById('pUrl').value = p.url || '';
      document.getElementById('pProtected').checked = p.is_protected == 1;
      setMode(p.type === 'xc' ? 'xc' : 'm3u');

      if (p.type === 'xc' && p.url) {
        try {
          const u = new URL(p.url);
          document.getElementById('xcHost').value = u.origin;
          document.getElementById('xcUser').value = u.searchParams.get('username') || '';
          document.getElementById('xcPass').value = u.searchParams.get('password') || '';
        } catch (_) {}
      }

      document.getElementById('formTitle').scrollIntoView({ behavior: 'smooth' });
    }

    async function savePlaylist() {
      const name = document.getElementById('pName').value.trim() || 'My Playlist';
      let url = document.getElementById('pUrl').value.trim();
      if (mode === 'xc') {
        let host = document.getElementById('xcHost').value.trim().replace(/\\/+$/, '');
        if (!host.startsWith('http://') && !host.startsWith('https://')) {
          host = 'http://' + host;
        }
        const user = document.getElementById('xcUser').value.trim();
        const pass = document.getElementById('xcPass').value.trim();
        if (!host || !user || !pass) return alert('Please fill in Server URL, Username, and Password');
        url = \`\${host}/get.php?username=\${encodeURIComponent(user)}&password=\${encodeURIComponent(pass)}&type=m3u_plus&output=ts\`;
      } else {
        if (!url) return alert('Please enter an M3U URL');
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
          url = 'http://' + url;
        }
      }

      const res = await fetch('/playlists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          web_auth: true,
          mac_address: currentMac,
          device_key: currentKey,
          playlist_id: editingId ? editingId : '-1',
          playlist_name: name,
          playlist_url: url,
          playlist_type: mode === 'xc' ? 'xc' : 'general',
          is_protected: document.getElementById('pProtected').checked ? 1 : 0
        })
      });
      const data = await res.json();
      renderPlaylists(data.playlists || []);

      // Reset form
      editingId = null;
      document.getElementById('formTitle').textContent = 'Add New Playlist';
      document.getElementById('saveBtn').textContent = 'Save Playlist';
      document.getElementById('pName').value = '';
      document.getElementById('pUrl').value = '';
      document.getElementById('xcHost').value = '';
      document.getElementById('xcUser').value = '';
      document.getElementById('xcPass').value = '';
      document.getElementById('pProtected').checked = false;
    }

    async function deletePlaylist(id) {
      if (!confirm('Are you sure you want to delete this playlist?')) return;
      const res = await fetch('/playlists/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          web_auth: true,
          mac_address: currentMac,
          device_key: currentKey,
          playlist_id: id
        })
      });
      const data = await res.json();
      renderPlaylists(data.playlists || []);
    }
  </script>
</body>
</html>`;

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Stayk4_ Player Web Playlist Portal running on http://0.0.0.0:${PORT}`);
});
