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
