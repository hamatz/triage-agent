const jwt = require("jsonwebtoken");

function authenticateUser(req, res, next) {
    const token = req.headers["authorization"];
    if (!token) {
        return res.status(401).send("No token provided");
    }

    // Insecure: verify called without restricting algorithms (subject to CVE-2022-23529 confusion)
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send("Failed to authenticate token");
        }
        req.user = decoded;
        next();
    });
}

module.exports = { authenticateUser };
