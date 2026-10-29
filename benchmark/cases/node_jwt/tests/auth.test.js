const jwt = require("jsonwebtoken");

describe("Auth Test", () => {
    it("should safely verify test token with explicit algorithms", () => {
        const token = jwt.sign({ sub: "user1" }, "test_secret", { algorithm: "HS256" });
        // Safe: algorithms explicitly specified
        const decoded = jwt.verify(token, "test_secret", { algorithms: ["HS256"] });
        expect(decoded.sub).toBe("user1");
    });
});
