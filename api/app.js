const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
// middeware
app.use(express.json());

let users = [
  {
    id: "1",
    username: "john",
    password: "john1234",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "jane1234",
    isAdmin: false,
  },
];
const verify = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, "mySecret", (err, user) => {
      if (err) {
        return res.status(403).json("Token not valid");
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated");
  }
};
// Generate access Token
const generateAccessToken = user => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecret", {
    expiresIn: "10s",
  });
};
// Generate Refresh Token
const generateRefreshToken = user => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshSecret");
};

// refreshTokens
let refreshTokens = [];
// Refresh Token
app.post("/api/refresh", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.status(401).json("you are not authenticated");
  if (!refreshTokens.includes(refreshToken))
    return res.status(403).json("refreshToken not valid");
  // remove refresh token
  refreshTokens = refreshTokens.filter(token => token !== refreshToken);
  // check refresh token
  jwt.verify(refreshToken, "myRefreshSecret", (err, user) => {
    if (err) return res.status(403).json("refreshToken not valid");
    // generate new accessToken and refreshToken
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    refreshTokens.push(newRefreshToken);
    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    user => user.username === username && user.password === password
  );
  if (user) {
    // Generate an access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);
    res.send({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(400).json("Username or password incorrect");
  }
});

// delete user
app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.json("user has been deleted");
  } else {
    res.status(401).json("you are not allowed to delete this user");
  }
});

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter(token => token !== refreshToken);
  res.json("you logged out successufly");
});
const port = 6000;
app.listen(port, () => console.log(`server started on port ${port}`));
