require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');
const mongoose = require('mongoose');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());

admin.initializeApp({
    credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        // The regex replaces literal \n with actual line breaks for the private key
        privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined
    })
});

// ==========================================
// 1. MONGODB CONNECTION & SCHEMAS
// ==========================================
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Atlas Connected Successfully!'))
    .catch(err => console.error('MongoDB Connection Error:', err));

const itemSchema = new mongoose.Schema({
    id: Number, 
    title: String, 
    price: String, 
    img: String, 
    site: String, 
    url: String, 
    bought: Boolean
});

// PHASE 4 UPGRADE: id is now a String (Alphanumeric), isPublic added.
const cartSchema = new mongoose.Schema({
    id: String, 
    name: String, 
    icon: String, 
    items: [itemSchema], 
    isPublic: { type: Boolean, default: false },
    lastModified: { type: Number, default: Date.now },
    createdAt: { type: Number, default: Date.now },
    isPinned: { type: Boolean, default: false }
});

const userSchema = new mongoose.Schema({
    firebaseUid: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    username: { type: String, lowercase: true, trim: true },
    displayUsername: { type: String, trim: true },
    pfp: String,
    lastUsernameChange: { type: Number, default: 0 },
    lastActive: { type: Number, default: Date.now },
    carts: [cartSchema]
});

const User = mongoose.model('User', userSchema);
const normalizeUser = (username) => username.trim().toLowerCase();

// ==========================================
// 2. FIREBASE AUTHENTICATION MIDDLEWARE
// ==========================================
async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized.' });
    try {
        req.user = await admin.auth().verifyIdToken(authHeader.split('Bearer ')[1]);
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Unauthorized. Invalid token.' });
    }
}

// ==========================================
// 2.5 UPTIME ROBOT KEEP-ALIVE PING
// ==========================================
app.get('/api/ping', (req, res) => {
    res.status(200).json({ status: "Awake", timestamp: Date.now() });
});

// ==========================================
// 3. USER SYNC & STATS 
// ==========================================
app.get('/api/stats', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const cartData = await User.aggregate([{ $project: { numCarts: { $size: "$carts" } } }, { $group: { _id: null, totalCarts: { $sum: "$numCarts" } } }]);
        const dailyActive = await User.countDocuments({ lastActive: { $gte: Date.now() - 86400000 } });
        res.json({ totalUsers, totalCarts: cartData.length ? cartData[0].totalCarts : 0, dailyActive });
    } catch (err) { res.status(500).json({ error: 'Failed to fetch stats.' }); }
});

app.post('/api/auth/sync', verifyToken, async (req, res) => {
    const { uid, email, name, picture } = req.user;
    try {
        let user = await User.findOne({ firebaseUid: uid });
        if (!user) {
            const baseUsername = name ? name.replace(/\s+/g, '') : email.split('@')[0];
            user = await User.create({
                firebaseUid: uid, email, username: normalizeUser(baseUsername), displayUsername: baseUsername,
                pfp: picture || `https://ui-avatars.com/api/?name=${baseUsername}&background=020617&color=fff&bold=true`
            });
        } else {
            user.lastActive = Date.now(); await user.save();
        }
        res.json({ message: 'Synced', user: { username: user.displayUsername, pfp: user.pfp, email: user.email } });
    } catch (err) { res.status(500).json({ error: 'Database sync failed.' }); }
});

app.get('/api/check-username/:username', async (req, res) => {
    res.json({ exists: !!(await User.exists({ username: normalizeUser(req.params.username) })) });
});

app.post('/api/user/update', verifyToken, async (req, res) => {
    const { newUsername, pfpUrl } = req.body;
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.lastActive = Date.now();
        if (newUsername && newUsername.trim() !== user.displayUsername) {
            const safeNew = normalizeUser(newUsername);
            if (safeNew !== user.username && await User.exists({ username: safeNew })) return res.status(400).json({ error: 'Username taken.' });
            if (Date.now() - user.lastUsernameChange < 604800000) return res.status(400).json({ error: `Must wait 7 days between changes.` });
            user.username = safeNew; user.displayUsername = newUsername.trim(); user.lastUsernameChange = Date.now();
        }
        if (pfpUrl) user.pfp = pfpUrl;
        await user.save();
        res.json({ success: true, newUsername: user.displayUsername, pfp: user.pfp });
    } catch (err) { res.status(500).json({ error: 'Update failed.' }); }
});

// ==========================================
// 4. THE SECURE CUSTOM MAILER
// ==========================================
const transporter = nodemailer.createTransport({
  host: 'smtp.hostinger.com', 
  port: 465, secure: true,
  auth: { user: 'no-reply@omni-cart.org', pass: '#Kylerraytull09092010' } 
});

app.post('/api/auth/send-reset-email', async (req, res) => {
    const { email, domainUrl } = req.body;

    try {
        const firebaseLink = await admin.auth().generatePasswordResetLink(email, { url: domainUrl });
        const urlObj = new URL(firebaseLink);
        const token = urlObj.searchParams.get('oobCode');
        const customResetLink = `${domainUrl}?action=reset&token=${token}`;

        const mailOptions = {
            from: '"OmniCart Team" <no-reply@omni-cart.org>',
            to: email,
            subject: 'Reset your OmniCart password',
            html: `
            <div style="font-family: 'Inter', Helvetica, Arial, sans-serif; color: #0f172a; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 12px;">
                <img src="https://i.imgur.com/loIOYD8.png" alt="OmniCart Banner" style="width: 100%; border-radius: 8px 8px 0 0; display: block; margin-bottom: 30px;">
                <div style="padding: 0 20px;">
                    <p style="font-size: 16px; line-height: 1.6;">Hi there,</p>
                    <p style="font-size: 16px; line-height: 1.6;">Someone (hopefully you) requested a password reset for your OmniCart account.</p>
                    <div style="text-align: center; margin: 40px 0;">
                        <a href="${customResetLink}" style="background-color: #020617; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 700; font-size: 16px; display: inline-block;">Reset your password &rsaquo;</a>
                    </div>
                    <p style="font-size: 14px; color: #64748b; line-height: 1.6;">This secure link expires shortly. If you did not request a password reset, you can safely ignore this email.</p>
                    <p style="font-size: 16px; line-height: 1.6; margin-top: 30px;">Best,<br><strong>The OmniCart Team</strong></p>
                </div>
                <hr style="border: 0; border-top: 1px solid #f1f5f9; margin: 40px 0 20px 0;">
                <p style="text-align: center; font-size: 12px; color: #94a3b8;">&copy; 2026 OmniCart, 525 Brannan St #300, San Francisco, CA 94107</p>
            </div>`
        };

        await transporter.sendMail(mailOptions);
        res.json({ success: true });
    } catch (error) {
        console.error("Email Generation Error:", error);
        res.status(500).json({ error: 'Failed to generate token or send email.' });
    }
});

// ==========================================
// 5. WORKSPACE (CART) SYNCING 
// ==========================================
app.get('/api/carts', verifyToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (user) { user.lastActive = Date.now(); await user.save(); res.json(user.carts || []); } 
        else { res.json([]); }
    } catch (err) { res.status(500).json({ error: 'Failed to fetch carts.' }); }
});

app.post('/api/carts', verifyToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.carts = req.body.carts; user.lastActive = Date.now(); await user.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Failed to save carts.' }); }
});

// ==========================================
// 6. PUBLIC READ-ONLY WORKSPACES
// ==========================================
app.get('/api/shared-cart/:cartId', async (req, res) => {
    try {
        const targetId = req.params.cartId;
        const user = await User.findOne({ "carts": { $elemMatch: { id: targetId, isPublic: true } } });

        if (!user) return res.status(404).json({ error: 'Workspace not found or is set to private.' });

        const sharedCart = user.carts.find(c => c.id === targetId);
        res.json({ success: true, ownerName: user.displayUsername, cart: sharedCart });

    } catch (err) {
        console.error("Shared Cart Error:", err);
        res.status(500).json({ error: 'Failed to fetch shared workspace data.' });
    }
});

// ==========================================
// 7. PHASE 1: UNIVERSAL WATERFALL SCRAPER
// ==========================================
app.post('/api/scrape', verifyToken, async (req, res) => {
    const { url } = req.body;

    const getSiteName = (fullUrl) => {
        try { return new URL(fullUrl).hostname.replace('www.', '').split('.')[0]; } 
        catch(e) { return 'web'; }
    };

    let title = '';
    let price = '';
    let img = '';
    let site = getSiteName(url);

    try {
        // MASK AS A HIGHLY CAPABLE DESKTOP BROWSER
        const headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'sec-ch-ua': '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        };

        const { data } = await axios.get(url, { timeout: 10000, headers });
        const $ = cheerio.load(data);
        
        // --- TACTIC 1: JSON-LD PARSING ---
        $('script[type="application/ld+json"]').each((i, el) => {
            try {
                // Brute force regex across the JSON string to catch nested properties
                const strData = $(el).html().trim();
                
                if (!title) {
                    const tMatch = strData.match(/"name"\s*:\s*"([^"]+)"/);
                    if (tMatch && tMatch[1].length > 3) title = tMatch[1];
                }
                if (!price) {
                    const pMatch = strData.match(/"price"\s*:\s*"?(\d+(\.\d{1,2})?)"?/);
                    if (pMatch) price = pMatch[1];
                }
                if (!img) {
                    const iMatch = strData.match(/"image"\s*:\s*\[?"([^"]+)"/);
                    if (iMatch) img = iMatch[1];
                }
            } catch(e){}
        });

        // --- TACTIC 2: BRUTE FORCE NEXT.JS / REACT STATE INJECTION ---
        // Hits Walmart, Target, BestBuy, and many others natively
        if (!price || !title) {
            const rawBody = data;
            if (!price) {
                const statePriceMatch = rawBody.match(/"currentPrice"\s*:\s*"?(\d+(\.\d{1,2})?)"?/) || 
                                        rawBody.match(/"price"\s*:\s*"?(\d+(\.\d{1,2})?)"?/);
                if (statePriceMatch) price = statePriceMatch[1];
            }
            if (!title) {
                const stateTitleMatch = rawBody.match(/"title"\s*:\s*"([^"]+)"/) || 
                                        rawBody.match(/"productName"\s*:\s*"([^"]+)"/);
                if (stateTitleMatch && stateTitleMatch[1].length > 5) title = stateTitleMatch[1];
            }
        }

        // --- TACTIC 3: OPENGRAPH & TWITTER META TAGS ---
        if (!title) title = $('meta[property="og:title"]').attr('content') || $('meta[name="twitter:title"]').attr('content');
        if (!img) img = $('meta[property="og:image"]').attr('content') || $('meta[name="twitter:image"]').attr('content') || $('meta[itemprop="image"]').attr('content');
        if (!price) price = $('meta[property="product:price:amount"]').attr('content') || $('meta[property="price"]').attr('content') || $('meta[itemprop="price"]').attr('content');
        
        const ogSite = $('meta[property="og:site_name"]').attr('content');
        if (ogSite) site = ogSite;

        // --- TACTIC 4: AGGRESSIVE DOM SELECTORS ---
        if (!title) {
            title = $('#productTitle').text() || // Amazon
                    '.product-title'.text() || 
                    '.pdp-title'.text() || // Generic e-comm
                    '[data-ui="product-title"]'.text() || // Target
                    'h1[itemprop="name"]'.text() || // Schema
                    'h1'.first().text() || 
                    $('title').text();
        }
        
        if (!img) {
            img = $('#landingImage').attr('src') || // Amazon
                  $('#imgBlkFront').attr('src') ||  // Amazon Books
                  $('#icImg').attr('src') || // eBay
                  $('.product-image img').attr('src') || 
                  $('.pdp-image img').attr('src') || 
                  $('img[data-old-hires]').attr('src');
                  
            // Final fallback: first valid non-icon image
            if(!img) {
                 $('img').each((i, el) => {
                     const src = $(el).attr('src');
                     if(src && !src.includes('icon') && !src.includes('logo') && !src.includes('spinner') && !img) {
                         img = src;
                     }
                 });
            }
        }
        
        if (!price) {
            const priceSelectors = [
                '.a-price .a-offscreen', // Amazon
                '#priceblock_ourprice',  // Amazon Old
                '.prc-IeVDy',            // eBay
                '[itemprop="price"]',    // Schema
                '[data-test="product-price"]', // Target
                '.price',                // Shopify
                '.product-price',        // Generic
                '.pdp-price',
                '[data-price]',
                '.CurrentPrice',
                '.Price--current'
            ];
            
            for (let sel of priceSelectors) {
                const pText = $(sel).first().text().trim();
                if (pText && pText.match(/\d/)) {
                    price = pText;
                    break;
                }
            }
        }

        // --- TACTIC 5: RAW REGEX BRUTE FORCE (If price is still missing) ---
        if (!price || price === '0.00' || price.trim() === '') {
            // Sweep entire HTML body for currency symbols near numbers
            const match = data.match(/[$£€]\s*(\d{1,3}(?:[.,]\d{3})*(?:\.\d{2})?)/);
            if (match) price = match[1].replace(/,/g, '');
        }

        // --- VALIDATION & CLEANUP ---
        
        if (title) {
            title = title.replace(/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,4}\s*[:|-]\s*/i, '').split(/\||\s-\s/)[0].trim().substring(0, 100);
        } else {
            title = 'Unknown Product';
        }

        if (price) {
            price = price.replace(/[^0-9.]/g, ''); 
        }
        if (!price || isNaN(parseFloat(price))) price = "0.00";

        const hasRealTitle = title !== 'Unknown Product';
        const hasRealPrice = price !== "0.00";
        const hasRealImg = img && !img.includes('ui-avatars') && img.length > 5;

        // --- COMPLETE FAILURE INTERCEPTION ---
        if (!hasRealTitle && !hasRealPrice && !hasRealImg) {
            return res.status(403).json({ error: "Failed to fetch any product info due to Anti-bot protections. Please add manually." });
        }

        if (!img || !hasRealImg) {
            img = `https://ui-avatars.com/api/?name=${encodeURIComponent(title.substring(0,2))}&background=random`;
        }

        // Determine Partial Status
        const isPartial = (!hasRealTitle || !hasRealPrice || !hasRealImg);

        res.json({ title, price, img, site, url, isPartial });

    } catch (err) { 
        // --- COMPLETE FAILURE / BLOCKED REQUEST ---
        return res.status(403).json({ error: "Failed to fetch any product info due to Anti-bot protections. Please add manually." });
    }
});

app.get('/', (req, res) => res.send('OmniCart V6 Universal Engine Online'));
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`OmniCart V6 Running on Port ${PORT}`));
