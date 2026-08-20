const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const app = express();

app.use(cors());
app.use(express.json());

// ==========================================
// HASHED LOGIN CREDENTIALS
// ==========================================

const users = {
    Associate: {
        loginId: "ASSOC001",
        passwordHash: "$2b$10$zuhZHXk/PenPdu8TQM6CY.Rf/MjcE4okhGadEnKrhDCKamE9mJVJ2"
    },

    Manager: {
        loginId: "MAN001",
        passwordHash: "$2b$10$rb69ah06k5x9kMiN5U689.CKqk58vyTjjqoU3.9czXfSFAIja.lhC"
    }
};


// ==========================================
// LOGIN API
// ==========================================

app.post("/login", async (req, res) => {

    try {

        const {
            name,
            loginId,
            password,
            role
        } = req.body;


        // Check fields

        if (
            !name ||
            !loginId ||
            !password ||
            !role
        ) {

            return res.status(400).json({
                success: false,
                message: "Please fill all the fields."
            });
        }


        // Check role

        const user = users[role];

        if (!user) {

            return res.status(401).json({
                success: false,
                message: "Invalid role selected."
            });
        }


        // Check Login ID

        if (loginId !== user.loginId) {

            return res.status(401).json({
                success: false,
                message: "Invalid Login ID."
            });
        }


        // Compare password with hash

        const passwordMatch =
            await bcrypt.compare(
                password,
                user.passwordHash
            );


        if (!passwordMatch) {

            return res.status(401).json({
                success: false,
                message: "Incorrect password."
            });
        }


        // Login successful

        res.json({
            success: true,
            message: "Login successful!",
            user: {
                name: name,
                role: role,
                loginId: loginId
            }
        });

    }

    catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message: "Server error."
        });
    }

});


// ==========================================
// TEST ROUTE
// ==========================================

app.get("/", (req, res) => {

    res.send("AI Automatic Roster Backend is running.");

});


// ==========================================
// SERVER
// ==========================================

app.listen(5000, () => {

    console.log(
        "Server running on http://localhost:5000"
    );

});