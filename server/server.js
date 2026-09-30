const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const PORT = 3000;

// =========================
// FILE PATHS
// =========================

const ROOT_DIR = path.join(__dirname, "..");
const USERS_FILE = path.join(ROOT_DIR, "users.json");

// =========================
// USERS FUNCTIONS
// =========================

function getUsers() {
    try {
        if (!fs.existsSync(USERS_FILE)) {
            fs.writeFileSync(USERS_FILE, "[]");
        }

        return JSON.parse(
            fs.readFileSync(USERS_FILE, "utf8")
        );
    } catch (error) {
        console.error("Error reading users.json:", error);
        return [];
    }
}

function saveUsers(users) {
    fs.writeFileSync(
        USERS_FILE,
        JSON.stringify(users, null, 2)
    );
}

// =========================
// MIDDLEWARE
// =========================

app.use(express.json());

// Serve CyberShield main folder
app.use(express.static(ROOT_DIR));

// =========================
// GET USERS
// =========================

app.get("/users", (req, res) => {
    const users = getUsers();

    res.json({
        success: true,
        users: users
    });
});

// =========================
// REGISTER VERIFIED PHONE
// =========================

app.post("/register-user", (req, res) => {

    const { phone } = req.body;

    if (!phone) {
        return res.status(400).json({
            success: false,
            message: "Phone number is required"
        });
    }

    const users = getUsers();

    const existingUser = users.find(
        user => user.phone === phone
    );

    if (existingUser) {

        existingUser.status = "Verified";

    } else {

        users.push({
            phone: phone,
            status: "Verified"
        });

    }

    saveUsers(users);

    res.json({
        success: true,
        message: "User registered successfully"
    });
});

// =========================
// CREATE ACCOUNT
// =========================

app.post("/register-account", async (req, res) => {

    try {

        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: "Username and password are required"
            });
        }

        if (username.length < 3) {
            return res.status(400).json({
                success: false,
                message: "Username must be at least 3 characters"
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 8 characters"
            });
        }

        const users = getUsers();

        const existingUser = users.find(
            user =>
                user.username &&
                user.username.toLowerCase() ===
                username.toLowerCase()
        );

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "Username already exists"
            });
        }

        const passwordHash = await bcrypt.hash(
            password,
            10
        );

        users.push({
            username: username,
            passwordHash: passwordHash,
            phone: "",
            status: "Not Verified"
        });

        saveUsers(users);

        res.json({
            success: true,
            message: "Account created successfully"
        });

    } catch (error) {

        console.error("Register error:", error);

        res.status(500).json({
            success: false,
            message: "Server error"
        });

    }
});

// =========================
// LOGIN
// =========================

app.post("/login", async (req, res) => {

    try {

        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: "Username and password are required"
            });
        }

        const users = getUsers();

        const user = users.find(
            user =>
                user.username &&
                user.username.toLowerCase() ===
                username.toLowerCase()
        );

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid username or password"
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.passwordHash
        );

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid username or password"
            });
        }

        res.json({
            success: true,
            message: "Login successful",
            user: {
                username: user.username,
                phone: user.phone,
                status: user.status
            }
        });

    } catch (error) {

        console.error("Login error:", error);

        res.status(500).json({
            success: false,
            message: "Server error"
        });

    }
});

// =========================
// OTP
// =========================

// Demo verification code
const verificationCode = "123456";

// Send OTP
app.post("/send-code", (req, res) => {

    const { phone } = req.body;

    if (!phone) {
        return res.status(400).json({
            success: false,
            message: "Phone number is required"
        });
    }

    res.json({
        success: true,
        message: "Verification code sent successfully"
    });
});

// Verify OTP
app.post("/verify-code", (req, res) => {

    const { code } = req.body;

    if (code === verificationCode) {

        return res.json({
            success: true,
            message: "Verification successful"
        });

    }

    res.status(400).json({
        success: false,
        message: "Invalid verification code"
    });
});

// =========================
// HOME
// =========================

app.get("/", (req, res) => {

    res.sendFile(
        path.join(ROOT_DIR, "index.html")
    );

});

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {

    console.log(
        `CyberShield server running on http://localhost:${PORT}`
    );

});