const jwt = require("jsonwebtoken");

function authenticateRequest(req) {
    const token = req.headers["authorization"];
    // Insecure: jwt.verify called without specifying algorithms array
    return jwt.verify(token, "secret-key");
}

module.exports = { authenticateRequest };
