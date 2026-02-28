require("dotenv").config();
const express = require("express");
const validator = require("validator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const logger = require("./logger");

const app = express();
app.use(express.json());

const users = [];

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "❌ Too many attempts, try later" },
});
app.use("/login", authLimiter);
app.use("/register", authLimiter);

// Logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url} - IP: ${req.ip}`);
  next();
});

// HTML Form - YEH PART CHANGE HUA HAI
app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Week 3 - Advanced Security</title>
      <style>
        body { font-family: Arial; padding: 20px; max-width: 600px; margin: 0 auto; }
        input, button { margin: 5px 0; padding: 10px; width: 100%; }
        .success { color: green; font-weight: bold; }
        #result { margin-top: 10px; padding: 10px; background: #f0f0f0; }
        .info { background: #e3f2fd; padding: 10px; margin: 10px 0; border-radius: 5px; }
      </style>
    </head>
    <body>
      <h1>🔒 Week 3: Advanced Security</h1>
      
      <div class="info">
        <b>Security Features:</b><br>
        ✅ Input Validation | ✅ Password Hashing | ✅ JWT Tokens<br>
        ✅ Rate Limiting | ✅ Logging | ✅ Penetration Testing
      </div>
      
      <h3>1️⃣ Register</h3>
      <input type="email" id="regEmail" placeholder="Email"><br>
      <input type="password" id="regPass" placeholder="Password (min 6)"><br>
      <button onclick="register()">Register</button>
      
      <h3>2️⃣ Login (Max 5 attempts per 15 min)</h3>
      <input type="email" id="logEmail" placeholder="Email"><br>
      <input type="password" id="logPass" placeholder="Password"><br>
      <button onclick="login()">Login</button>
      <div id="loginStatus"></div>
      
      <h3>3️⃣ Dashboard (Protected)</h3>
      <button onclick="dashboard()">View Dashboard</button>
      
      <h3>4️⃣ Test Security</h3>
      <button onclick="testSQLInjection()">Test SQL Injection</button>
      <button onclick="testXSS()">Test XSS</button>
      
      <div id="result"></div>

      <script>
        async function register() {
          try {
            const email = document.getElementById('regEmail').value;
            const password = document.getElementById('regPass').value;
            console.log('Registering:', email);
            
            const res = await fetch('/register', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({email, password})
            });
            
            const data = await res.json();
            console.log('Response:', data);
            document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
          } catch(e) {
            console.error('Error:', e);
            alert('Error: ' + e.message);
          }
        }

        async function login() {
          try {
            const email = document.getElementById('logEmail').value;
            const password = document.getElementById('logPass').value;
            console.log('Logging in:', email);
            
            const res = await fetch('/login', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({email, password})
            });
            
            const data = await res.json();
            console.log('Response:', data);
            
            if(data.token) {
              localStorage.setItem('token', data.token);
              document.getElementById('loginStatus').innerHTML = '<span class="success">✅ TOKEN SAVED!</span>';
            }
            
            document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
          } catch(e) {
            console.error('Error:', e);
            alert('Error: ' + e.message);
          }
        }

        async function dashboard() {
          try {
            const token = localStorage.getItem('token');
            console.log('Token:', token);
            
            if(!token) {
              document.getElementById('result').innerHTML = '<pre>{"error": "❌ Pehle login karo!"}</pre>';
              return;
            }
            
            const res = await fetch('/dashboard', {
              headers: {'Authorization': 'Bearer ' + token}
            });
            
            const data = await res.json();
            console.log('Response:', data);
            document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
          } catch(e) {
            console.error('Error:', e);
            alert('Error: ' + e.message);
          }
        }

        async function testSQLInjection() {
          const res = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email: "' OR '1'='1", password: "anything"})
          });
          const data = await res.json();
          alert('SQL Injection Test: ' + JSON.stringify(data));
        }

        async function testXSS() {
          const res = await fetch('/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email: "<script>alert('xss')</script>@test.com", password: "password123"})
          });
          const data = await res.json();
          alert('XSS Test: ' + JSON.stringify(data));
        }
      </script>
    </body>
    </html>
  `);
});

// API ROUTES
app.post("/register", async (req, res) => {
  try {
    logger.info(`Register attempt: ${req.body.email}`);
    const { email, password } = req.body;

    if (!validator.isEmail(email)) {
      logger.warn(`Invalid email: ${email}`);
      return res.status(400).json({ error: "❌ Invalid email!" });
    }

    if (password.length < 6) {
      logger.warn(`Password too short`);
      return res
        .status(400)
        .json({ error: "❌ Password must be 6+ characters!" });
    }

    if (users.find((u) => u.email === email)) {
      logger.warn(`User exists: ${email}`);
      return res.status(400).json({ error: "❌ User already exists!" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = { id: users.length + 1, email, password: hashed };
    users.push(user);

    logger.info(`User registered: ${email}`);
    res.json({ message: "✅ User registered!", userId: user.id });
  } catch (err) {
    logger.error(`Register error: ${err.message}`);
    res.status(500).json({ error: "❌ Server error!" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    logger.info(`Login attempt: ${email}`);

    const user = users.find((u) => u.email === email);
    if (!user) {
      logger.warn(`User not found: ${email}`);
      return res.status(400).json({ error: "❌ User not found!" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      logger.warn(`Wrong password: ${email}`);
      return res.status(400).json({ error: "❌ Wrong password!" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    logger.info(`Login successful: ${email}`);
    res.json({ message: "✅ Login successful!", token });
  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    res.status(500).json({ error: "❌ Server error!" });
  }
});

app.get("/dashboard", (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) {
      logger.warn("Dashboard access without token");
      return res.status(401).json({ error: "❌ No token!" });
    }

    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = users.find((u) => u.id === decoded.id);

    logger.info(`Dashboard accessed: ${user.email}`);
    res.json({
      message: "✅ Welcome to Dashboard!",
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    logger.error(`Dashboard error: ${err.message}`);
    res.status(403).json({ error: "❌ Invalid token!" });
  }
});

// Error handling
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`);
  res.status(500).json({ error: "❌ Internal server error" });
});
app.listen(8080, () => {
  logger.info("✅ Server started on port 8080");
  console.log("✅ Server running on port 8080");
});
