const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcrypt');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();
app.use(cors());
app.use(express.json());

const DB_FILE = './database.json';

// Initialize Database
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: {} }, null, 4));
}

const readDB = () => JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const writeDB = (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 4));

// Helper: Normalize Usernames for Case Insensitivity
const normalizeUser = (username) => username.trim().toLowerCase();

// ==========================================
// 1. GLOBAL STATS ENGINE (Real Live Data)
// ==========================================
app.get('/api/stats', (req, res) => {
    const db = readDB();
    let totalUsers = 0;
    let totalCarts = 0;
    let dailyActive = 0;
    
    const now = Date.now();
    const ONE_DAY = 24 * 60 * 60 * 1000;

    for (const userKey in db.users) {
        totalUsers++;
        const user = db.users[userKey];
        
        if (user.carts) {
            totalCarts += user.carts.length;
        }
        
        if (user.lastActive && (now - user.lastActive < ONE_DAY)) {
            dailyActive++;
        }
    }

    res.json({ totalUsers, totalCarts, dailyActive });
});

// ==========================================
// 2. AUTHENTICATION & USER MANAGEMENT
// ==========================================

// Live Username Checker
app.get('/api/check-username/:username', (req, res) => {
    const db = readDB();
    const safeUser = normalizeUser(req.params.username);
    res.json({ exists: !!db.users[safeUser] });
});

// Register Account
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    const safeUser = normalizeUser(username);
    const db = readDB();
    
    if (db.users[safeUser]) {
        return res.status(400).json({ error: 'Username taken.' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    db.users[safeUser] = { 
        displayUsername: username.trim(), // Store the original casing for UI
        password: hashedPassword, 
        carts: [],
        pfp: `https://ui-avatars.com/api/?name=${username}&background=020617&color=fff&bold=true`,
        lastUsernameChange: 0,
        lastActive: Date.now()
    };
    
    writeDB(db);
    res.json({ message: 'Account created!', user: { username: db.users[safeUser].displayUsername, pfp: db.users[safeUser].pfp } });
});

// Login Account
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const safeUser = normalizeUser(username);
    const db = readDB();
    const user = db.users[safeUser];
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Incorrect username or password.' });
    }
    
    user.lastActive = Date.now();
    writeDB(db);
    
    res.json({ message: 'Login successful!', user: { username: user.displayUsername, pfp: user.pfp } });
});

// Fetch Profile Data (7-day lock check)
app.get('/api/user/profile/:username', (req, res) => {
    const safeUser = normalizeUser(req.params.username);
    const db = readDB();
    const user = db.users[safeUser];
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ lastUsernameChange: user.lastUsernameChange, pfp: user.pfp });
});

// Update Profile (Requires Password)
app.post('/api/user/update', async (req, res) => {
    const { currentUsername, newUsername, pfpUrl, password } = req.body;
    const safeCurrent = normalizeUser(currentUsername);
    const db = readDB();
    const user = db.users[safeCurrent];
    
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (!(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Incorrect password.' });
    }

    let updatedDisplayUsername = user.displayUsername;
    user.lastActive = Date.now();

    if (newUsername && newUsername.trim() !== user.displayUsername) {
        const safeNew = normalizeUser(newUsername);
        
        if (safeNew !== safeCurrent && db.users[safeNew]) {
            return res.status(400).json({ error: 'Username already taken.' });
        }
        
        const now = Date.now();
        const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000;
        
        if (user.lastUsernameChange && (now - user.lastUsernameChange < SEVEN_DAYS)) {
            const daysLeft = Math.ceil((SEVEN_DAYS - (now - user.lastUsernameChange)) / (1000 * 60 * 60 * 24));
            return res.status(400).json({ error: `You must wait ${daysLeft} more days to change your username.` });
        }
        
        // Migrate data
        db.users[safeNew] = { 
            ...user, 
            displayUsername: newUsername.trim(),
            lastUsernameChange: now, 
            pfp: pfpUrl || user.pfp 
        };
        
        if (safeNew !== safeCurrent) {
            delete db.users[safeCurrent];
        }
        
        updatedDisplayUsername = db.users[safeNew].displayUsername;
    } else {
        user.pfp = pfpUrl || user.pfp;
    }
    
    writeDB(db);
    
    // Find the current valid user record to return
    const finalUser = db.users[normalizeUser(updatedDisplayUsername)];
    res.json({ success: true, newUsername: finalUser.displayUsername, pfp: finalUser.pfp });
});

app.post('/api/user/password', async (req, res) => {
    const { username, oldPassword, newPassword } = req.body;
    const safeUser = normalizeUser(username);
    const db = readDB();
    const user = db.users[safeUser];
    
    if (!user || !(await bcrypt.compare(oldPassword, user.password))) {
        return res.status(401).json({ error: 'Incorrect current password.' });
    }
    
    user.password = await bcrypt.hash(newPassword, 10);
    user.lastActive = Date.now();
    writeDB(db);
    res.json({ success: true });
});

// ==========================================
// 3. WORKSPACE (CART) SYNCING
// ==========================================

app.get('/api/carts/:username', (req, res) => {
    const safeUser = normalizeUser(req.params.username);
    const db = readDB();
    
    if (db.users[safeUser]) {
        db.users[safeUser].lastActive = Date.now();
        writeDB(db);
    }
    
    res.json(db.users[safeUser]?.carts || []);
});

app.post('/api/carts/:username', (req, res) => {
    const safeUser = normalizeUser(req.params.username);
    const db = readDB();
    
    if (!db.users[safeUser]) return res.status(404).json({ error: 'User not found' });
    
    db.users[safeUser].carts = req.body.carts;
    db.users[safeUser].lastActive = Date.now();
    writeDB(db);
    
    res.json({ success: true });
});

// ==========================================
// 4. ADVANCED WEB SCRAPER (Timeout & Firewall Handling)
// ==========================================

app.post('/api/scrape', async (req, res) => {
    const { url } = req.body;
    try {
        // Strict 4-Second Timeout to fail fast on BestBuy/Walmart hangs
        const { data } = await axios.get(url, { 
            timeout: 4000,
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            } 
        });
        
        const $ = cheerio.load(data);
        
        // Title Parser
        let rawTitle = $('meta[property="og:title"]').attr('content') || $('title').text() || 'Unknown Product';
        rawTitle = rawTitle.replace(/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,4}\s*[:|-]\s*/i, '');
        let cleanTitle = rawTitle.split(/,|\||\s-\s/)[0].trim();

        // Image Parser
        let img = $('meta[property="og:image"]').attr('content') || 
                  $('meta[name="twitter:image"]').attr('content') || 
                  $('#landingImage').attr('src') || 
                  $('link[rel="image_src"]').attr('href') || 
                  'https://via.placeholder.com/150?text=No+Image';

        // Price Parser
        let price = "0.00";
        
        // JSON-LD Check
        $('script[type="application/ld+json"]').each((i, el) => {
            try {
                const json = JSON.parse($(el).html());
                if (json.offers && json.offers.price) {
                    price = json.offers.price.toString();
                } else if (Array.isArray(json)) {
                    for(let j of json) {
                        if(j.offers && j.offers.price) price = j.offers.price.toString();
                    }
                }
            } catch(e) {}
        });

        // HTML Class Check
        if (price === "0.00" || price === "") {
            const priceSelectors = [
                'meta[property="product:price:amount"]',
                '.a-price .a-offscreen', 
                '#corePriceDisplay_desktop_feature_div .a-price-whole',
                '[data-testid="customer-price"]', 
                '.priceView-hero-price span[aria-hidden="true"]', 
                '.price-characteristic'
            ];
            
            for (let sel of priceSelectors) {
                let pText = $(sel).first().text() || $(sel).first().attr('content');
                if (pText) {
                    let match = pText.match(/\d+(?:,\d{3})*(?:\.\d{2})?/);
                    if (match) {
                        price = match[0].replace(',', '');
                        break;
                    }
                }
            }
        }

        // Blind Regex Fallback
        if (price === "0.00" || price === "") {
            const priceMatch = data.match(/\$\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)/);
            if (priceMatch) price = priceMatch[1].replace(',', '');
        }

        let site = new URL(url).hostname.replace('www.', '').split('.')[0];
        res.json({ title: cleanTitle.substring(0, 80), price, img, site, url });
        
    } catch (err) {
        // If it hangs for 4 seconds, hits a firewall, or fails, send 'blocked'
        res.status(500).json({ error: 'blocked' });
    }
});

app.listen(3000, () => console.log('Running on Port 3000'));