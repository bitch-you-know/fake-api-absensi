const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./database.json'); // Data untuk endpoint utama
const userdbPath = './users.json'; // Data untuk endpoint /users
const databasePath = './database.json';

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
  const data = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  return data.users.findIndex(user => user.email === email && user.password === password) !== -1;
}

// Convert UTC time to WIB
function convertToWIB(date) {
  const utcDate = new Date(date);
  const WIB_OFFSET = 7 * 60 * 60 * 1000; // WIB is UTC+7
  const wibDate = new Date(utcDate.getTime() + WIB_OFFSET);
  return wibDate.toISOString().replace('T', ' ').slice(0, -1); // Format to "YYYY-MM-DD HH:MM:SS"
}

// Save login activity
function saveLoginActivity(email) {
  const loginTime = convertToWIB(new Date().toISOString());
  const database = JSON.parse(fs.readFileSync(databasePath, 'UTF-8'));

  database.attendance = database.attendance || [];
  const attendanceEntry = {
    email: email,
    loginTime: loginTime,
    logoutTime: null // Will be updated on logout
  };

  database.attendance.push(attendanceEntry);
  fs.writeFileSync(databasePath, JSON.stringify(database, null, 2));
}

// Update logout activity
function updateLogoutActivity(email) {
  const logoutTime = convertToWIB(new Date().toISOString());
  const database = JSON.parse(fs.readFileSync(databasePath, 'UTF-8'));

  const attendanceEntry = database.attendance.find(record => record.email === email && record.logoutTime === null);
  if (attendanceEntry) {
    attendanceEntry.logoutTime = logoutTime;
    fs.writeFileSync(databasePath, JSON.stringify(database, null, 2));
  }
}

// Login endpoint
server.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!isAuthenticated({ email, password })) {
    const status = 401;
    const message = 'Incorrect email or password';
    res.status(status).json({ status, message });
    return;
  }

  // Create token
  const access_token = createToken({ email, password });
  saveLoginActivity(email); // Record login activity

  res.status(200).json({ access_token });
});

// Register New User
server.post('/auth/register', (req, res) => {
  console.log("register endpoint called; request body:");
  console.log(req.body);

  const { email, password, divisi, nama, alamat, role } = req.body;

  if (isAuthenticated({ email, password })) {
    const status = 401;
    const message = 'Email and Password already exist';
    res.status(status).json({ status, message });
    return;
  }

  fs.readFile(userdbPath, (err, data) => {
    if (err) {
      const status = 500; // Internal server error
      const message = err.message;
      res.status(status).json({ status, message });
      return;
    }

    // Get current users data
    var data = JSON.parse(data.toString());

    // Get the id of last user
    var last_item_id = data.users[data.users.length - 1]?.id || 0;

    // Add new user with additional fields including role
    data.users.push({ 
      id: last_item_id + 1, 
      email: email, 
      password: password,
      divisi: divisi,
      nama: nama,
      alamat: alamat,
      role: role // Adding role here
    });

    fs.writeFile(userdbPath, JSON.stringify(data), (err) => {  // WRITE
      if (err) {
        const status = 500; // Internal server error
        const message = err.message;
        res.status(status).json({ status, message });
        return;
      }

      // Create token for new user
      const access_token = createToken({ email, password, role });
      console.log("Access Token:" + access_token);
      res.status(200).json({ access_token });
    });
  });
});

// Logout endpoint
server.post('/auth/logout', (req, res) => {
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401;
    const message = 'Error in authorization format';
    res.status(status).json({ status, message });
    return;
  }

  try {
    const token = req.headers.authorization.split(' ')[1];
    const verifyTokenResult = verifyToken(token);

    if (verifyTokenResult instanceof Error) {
      const status = 401;
      const message = 'Access token not provided';
      res.status(status).json({ status, message });
      return;
    }

    // Update logout activity
    updateLogoutActivity(verifyTokenResult.email);

    res.status(200).json({ message: 'Logout successful' });
  } catch (err) {
    const status = 401;
    const message = 'Error access_token is revoked';
    res.status(status).json({ status, message });
  }
});

// Middleware to check if user is authenticated before accessing other routes
server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401;
    const message = 'Error in authorization format';
    res.status(status).json({ status, message });
    return;
  }

  try {
    let verifyTokenResult;
    verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

    if (verifyTokenResult instanceof Error) {
      const status = 401;
      const message = 'Access token not provided';
      res.status(status).json({ status, message });
      return;
    }
    next();
  } catch (err) {
    const status = 401;
    const message = 'Error access_token is revoked';
    res.status(status).json({ status, message });
  }
});

// Get all users
server.get('/users', (req, res) => {
  const data = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  res.json(data);
});

// Get a user by ID
server.get('/users/:id', (req, res) => {
  const data = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  const user = data.users.find(u => u.id === parseInt(req.params.id));
  if (user) {
    res.json(user);
  } else {
    res.status(404).json({ status: 404, message: 'User not found' });
  }
});

// Update a user by ID
server.put('/users/:id', (req, res) => {
  const { email, password, divisi, nama, alamat } = req.body;
  const data = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  const userIndex = data.users.findIndex(u => u.id === parseInt(req.params.id));

  if (userIndex !== -1) {
    data.users[userIndex] = {
      id: parseInt(req.params.id),
      email,
      password,
      divisi,
      nama,
      alamat
    };

    fs.writeFileSync(userdbPath, JSON.stringify(data, null, 2));
    res.json(data.users[userIndex]);
  } else {
    res.status(404).json({ status: 404, message: 'User not found' });
  }
});

// Delete a user by ID
server.delete('/users/:id', (req, res) => {
  const data = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  const userIndex = data.users.findIndex(u => u.id === parseInt(req.params.id));

  if (userIndex !== -1) {
    data.users.splice(userIndex, 1);
    fs.writeFileSync(userdbPath, JSON.stringify(data, null, 2));
    res.status(204).end();
  } else {
    res.status(404).json({ status: 404, message: 'User not found' });
  }
});

server.use(router);

server.listen(8000, () => {
  console.log('Run Auth API Server');
});
