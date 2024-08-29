const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./database.json');
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'));
const loginLogoutFile = './login-logout.json';

// Middleware setup
server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789';
const expiresIn = '1h';

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ? decode : err);
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  return userdb.users.findIndex(user => user.email === email && user.password === password) !== -1;
}

// Log login/logout activity
function logActivity(email, action) {
  const now = new Date();
  const timestampUTC = now.toISOString(); // Waktu dalam format UTC
  
  // Konversi waktu UTC ke WIB (UTC+7)
  const timestampWIB = new Date(now.getTime() + 7 * 60 * 60 * 1000).toISOString(); // Format: YYYY-MM-DDTHH:MM:SS.sssZ

  fs.readFile(loginLogoutFile, (err, data) => {
    if (err && err.code === 'ENOENT') {
      // File does not exist, initialize with empty array
      fs.writeFile(loginLogoutFile, JSON.stringify([]), err => {
        if (err) {
          console.error('Error initializing login-logout file:', err);
        } else {
          console.log('Initialized login-logout file');
        }
      });
    } else if (err) {
      console.error('Error reading login-logout file:', err);
      return;
    }
    
    let logs;
    try {
      logs = JSON.parse(data.toString());
    } catch (e) {
      console.error('Error parsing login-logout file:', e);
      logs = [];
    }
    
    logs.push({ email, action, timestamp: timestampWIB });
    
    fs.writeFile(loginLogoutFile, JSON.stringify(logs, null, 2), err => {
      if (err) {
        console.error('Error writing login-logout file:', err);
      } else {
        console.log('Successfully logged activity:', { email, action, timestamp: timestampWIB });
      }
    });
  });
}

// Register New User
server.post('/auth/register', (req, res) => {
  console.log("register endpoint called; request body:");
  console.log(req.body);
  const { email, password } = req.body;

  if (isAuthenticated({ email, password })) {
    const status = 401;
    const message = 'Email and Password already exist';
    res.status(status).json({ status, message });
    return;
  }

  fs.readFile("./users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    let dataJson = JSON.parse(data.toString());
    let lastItemId = dataJson.users[dataJson.users.length - 1].id;
    dataJson.users.push({ id: lastItemId + 1, email: email, password: password });

    fs.writeFile("./users.json", JSON.stringify(dataJson), err => {
      if (err) {
        const status = 401;
        const message = err;
        res.status(status).json({ status, message });
        return;
      }
    });
  });

  const access_token = createToken({ email, password });
  console.log("Access Token:" + access_token);
  res.status(200).json({ access_token });
});

// Login to one of the users from ./users.json
server.post('/auth/login', (req, res) => {
  console.log("login endpoint called; request body:");
  console.log(req.body);
  const { email, password } = req.body;
  
  if (!isAuthenticated({ email, password })) {
    const status = 401;
    const message = 'Incorrect email or password';
    res.status(status).json({ status, message });
    return;
  }

  // Log the login activity
  logActivity(email, 'login');

  const access_token = createToken({ email, password });
  console.log("Access Token:" + access_token);
  res.status(200).json({ access_token });
});

// Middleware to check authorization
server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401;
    const message = 'Error in authorization format';
    res.status(status).json({ status, message });
    return;
  }
  
  try {
    let verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

    if (verifyTokenResult instanceof Error) {
      const status = 401;
      const message = 'Access token not provided';
      res.status(status).json({ status, message });
      return;
    }
    
    // Log the logout activity
    logActivity(verifyTokenResult.email, 'logout');

    next();
  } catch (err) {
    const status = 401;
    const message = 'Error access_token is revoked';
    res.status(status).json({ status, message });
  }
});

server.use(router);

// Endpoint to get login/logout activity
server.get('/activity', (req, res) => {
  fs.readFile(loginLogoutFile, (err, data) => {
    if (err) {
      const status = 500;
      const message = 'Error reading login-logout file';
      res.status(status).json({ status, message });
      return;
    }

    try {
      const logs = JSON.parse(data.toString());
      res.status(200).json(logs);
    } catch (e) {
      const status = 500;
      const message = 'Error parsing login-logout file';
      res.status(status).json({ status, message });
    }
  });
});

server.listen(8000, () => {
  console.log('Run Auth API Server http://localhost:8000');
});
