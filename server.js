const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json());


// ==========================================
// POSTGRESQL CONNECTION
// ==========================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});


// ==========================================
// TEST DATABASE CONNECTION
// ==========================================

pool.connect()
    .then(client => {
        console.log("PostgreSQL connected successfully.");
        client.release();
    })
    .catch(error => {
        console.error(
            "PostgreSQL connection error:",
            error.message
        );
    });


// ==========================================
// CREATE USERS TABLE
// ==========================================

async function createUsersTable() {

    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                login_id VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);


        // ======================================
        // CREATE DEFAULT USERS
        // ======================================

        const associateHash =
            await bcrypt.hash("Viji@2006", 10);

        const managerHash =
            await bcrypt.hash("Manager@123", 10);


        await pool.query(`
            INSERT INTO users
                (name, login_id, password_hash, role)
            VALUES
                ('Associate User', 'ASSOC001', $1, 'Associate'),
                ('Manager User', 'MAN001', $2, 'Manager')
            ON CONFLICT (login_id) DO NOTHING;
        `, [
            associateHash,
            managerHash
        ]);


        console.log("Default users are ready.");
        console.log("Users table is ready.");

    }

    catch (error) {

        console.error(
            "Users table error:",
            error.message
        );
    }
}


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


        // ======================================
        // CHECK EMPTY FIELDS
        // ======================================

        if (
            !name ||
            !loginId ||
            !password ||
            !role
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Please fill all the fields."

            });
        }


        // ======================================
        // FIND USER
        // ======================================

        const result = await pool.query(

            `
            SELECT
                id,
                name,
                login_id,
                password_hash,
                role
            FROM users
            WHERE login_id = $1
            AND role = $2
            `,

            [
                loginId,
                role
            ]
        );


        // ======================================
        // USER NOT FOUND
        // ======================================

        if (result.rows.length === 0) {

            return res.status(401).json({

                success: false,

                message:
                    "Invalid Login ID or role."

            });
        }


        const user = result.rows[0];


        // ======================================
        // CHECK PASSWORD
        // ======================================

        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password_hash
            );


        if (!passwordMatch) {

            return res.status(401).json({

                success: false,

                message:
                    "Incorrect password."

            });
        }


        // ======================================
        // LOGIN SUCCESS
        // ======================================

        res.json({

            success: true,

            message:
                "Login successful!",

            user: {

                id:
                    user.id,

                name:
                    user.name,

                role:
                    user.role,

                loginId:
                    user.login_id

            }

        });

    }

    catch (error) {

        console.error(
            "Login error:",
            error
        );

        res.status(500).json({

            success: false,

            message:
                "Server error."

        });
    }

});
















// ==========================================
// CREATE ASSOCIATE USER API
// ==========================================

app.post("/create-associate", async (req, res) => {

    try {

        const {
            name,
            loginId,
            temporaryPassword
        } = req.body;


        // ======================================
        // CHECK EMPTY FIELDS
        // ======================================

        if (
            !name ||
            !loginId ||
            !temporaryPassword
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Please fill all the fields."

            });
        }


        // ======================================
        // PASSWORD LENGTH
        // ======================================

        if (temporaryPassword.length < 8) {

            return res.status(400).json({

                success: false,

                message:
                    "Temporary password must be at least 8 characters."

            });
        }


        // ======================================
        // CHECK LOGIN ID
        // ======================================

        const existingUser =
            await pool.query(

                `
                SELECT id
                FROM users
                WHERE login_id = $1
                `,

                [loginId]

            );


        if (existingUser.rows.length > 0) {

            return res.status(409).json({

                success: false,

                message:
                    "Login ID already exists."

            });
        }


        // ======================================
        // HASH TEMPORARY PASSWORD
        // ======================================

        const passwordHash =
            await bcrypt.hash(
                temporaryPassword,
                10
            );


        // ======================================
        // CREATE ASSOCIATE
        // ======================================

        const result =
            await pool.query(

                `
                INSERT INTO users
                    (
                        name,
                        login_id,
                        password_hash,
                        role
                    )
                VALUES
                    ($1, $2, $3, 'Associate')
                RETURNING
                    id,
                    name,
                    login_id,
                    role
                `,

                [
                    name,
                    loginId,
                    passwordHash
                ]

            );


        // ======================================
        // SUCCESS
        // ======================================

        res.status(201).json({

            success: true,

            message:
                "Associate account created successfully.",

            user:
                result.rows[0]

        });

    }

    catch (error) {

        console.error(
            "Create associate error:",
            error
        );

        res.status(500).json({

            success: false,

            message:
                "Server error."

        });

    }

});




















// ==========================================
// CHANGE PASSWORD API
// ==========================================

app.post("/change-password", async (req, res) => {

    try {

        const {
            loginId,
            currentPassword,
            newPassword,
            confirmPassword
        } = req.body;


        // ======================================
        // CHECK EMPTY FIELDS
        // ======================================

        if (
            !loginId ||
            !currentPassword ||
            !newPassword ||
            !confirmPassword
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Please fill all the fields."

            });
        }


        // ======================================
        // CHECK NEW PASSWORD MATCH
        // ======================================

        if (newPassword !== confirmPassword) {

            return res.status(400).json({

                success: false,

                message:
                    "New passwords do not match."

            });
        }


        // ======================================
        // PASSWORD LENGTH
        // ======================================

        if (newPassword.length < 8) {

            return res.status(400).json({

                success: false,

                message:
                    "Password must be at least 8 characters."

            });
        }


        // ======================================
        // FIND USER
        // ======================================

        const result = await pool.query(

            `
            SELECT
                id,
                password_hash
            FROM users
            WHERE login_id = $1
            `,

            [loginId]

        );


        // ======================================
        // USER NOT FOUND
        // ======================================

        if (result.rows.length === 0) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found."

            });
        }


        const user = result.rows[0];


        // ======================================
        // VERIFY CURRENT PASSWORD
        // ======================================

        const passwordMatch =
            await bcrypt.compare(
                currentPassword,
                user.password_hash
            );


        if (!passwordMatch) {

            return res.status(401).json({

                success: false,

                message:
                    "Current password is incorrect."

            });
        }


        // ======================================
        // HASH NEW PASSWORD
        // ======================================

        const newPasswordHash =
            await bcrypt.hash(
                newPassword,
                10
            );


        // ======================================
        // UPDATE DATABASE
        // ======================================

        await pool.query(

            `
            UPDATE users
            SET password_hash = $1
            WHERE id = $2
            `,

            [
                newPasswordHash,
                user.id
            ]

        );


        // ======================================
        // SUCCESS
        // ======================================

        res.json({

            success: true,

            message:
                "Password changed successfully."

        });

    }

    catch (error) {

        console.error(
            "Change password error:",
            error
        );

        res.status(500).json({

            success: false,

            message:
                "Server error."

        });
    }

});


// ==========================================
// TEST ROUTE
// ==========================================

app.get("/", (req, res) => {

    res.send(
        "AI Automatic Roster Backend is running."
    );

});


// ==========================================
// SERVER
// ==========================================

const PORT =
    process.env.PORT || 5000;


app.listen(
    PORT,
    "0.0.0.0",
    async () => {

        console.log(
            `Server running on port ${PORT}`
        );

        await createUsersTable();

    }
);
