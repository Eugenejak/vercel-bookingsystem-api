import express from "express";
let path = require("path");
import cors from "cors";
import pkg from "pg";
const { Pool } = pkg;
const { DATABASE_URL, SECRET_KEY } = process.env;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { getStreamToken } = require("./streamToken");
require("dotenv").config();

let app = express();
app.use(
    cors({
        origin: [
            "https://booking-system-ecru-five.vercel.app", // your Vercel frontend
            "http://localhost:5173", // local dev (Vite)
        ],
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
        credentials: true,
    }),
);

app.use(express.json());

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        require: true,
    },
});

app.get("/version", async (req, res) => {
    try {
        const result = await pool.query("SELECT version()");
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Signup endpoint
app.post("/signup", async (req, res) => {
    const client = await pool.connect();
    try {
        const { name, email, password } = req.body;

        // Check for input validation
        if (!name || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Check for existing email
        const emailResult = await client.query(
            "SELECT * FROM users WHERE email = $1",
            [email],
        );

        // If email already exists, return response
        if (emailResult.rows.length > 0) {
            return res.status(400).json({ message: "Email already registered." });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 12);

        // If email doesn't exist, then proceed with registration
        await client.query(
            "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)",
            [name, email, hashedPassword, "customer"],
        );

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Error: ", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// Login endpoint
app.post("/login", async (req, res) => {
    const client = await pool.connect();
    try {
        const result = await client.query("SELECT * FROM users WHERE email = $1", [
            req.body.email,
        ]);

        // If user found, store it in 'user' variable
        const user = result.rows[0];

        // If user not found, return an error response
        if (!user)
            return res.status(400).json({ message: "Email or password incorrect" });

        // Verify if password provided from request's body is the same with user's actual password
        const correctPassword = await bcrypt.compare(
            req.body.password,
            user.password,
        );
        if (!correctPassword)
            return res.status(401).json({ auth: false, token: null });

        // Else, pass in 3 arguments to jwt.sign() method to generate JWT token
        var token = jwt.sign(
            { id: user.id, name: user.name, email: user.email, role: user.role },
            SECRET_KEY,
            { expiresIn: 86400 },
        );

        // Return token back to user (front-end)
        res.status(200).json({ auth: true, token: token });
    } catch (error) {
        console.error("Error: ", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

app.get("/profile", (req, res) => {
    // Check if the Authorization bearer token was provided
    const authToken = req.headers.authorization;

    if (!authToken) return res.status(401).json({ error: "Access Denied" });

    try {
        // Verify the token and fetch the user infos
        const verified = jwt.verify(authToken, SECRET_KEY);
        res.json({
            // Fetch the infos from the token
            name: verified.name,
            email: verified.email,
            role: verified.role,
        });
    } catch (error) {
        // Return an error if token invalid
        res.status(400).json({ error: "Invalid Token" });
    }
});

// Show courts
app.get("/courts", async (req, res) => {
    const client = await pool.connect();
    try {
        let query = "SELECT * FROM courts";
        const values = [];

        // Get filter from query params
        const { sport_type } = req.query;

        if (sport_type) {
            query += " WHERE sport_type = $1 ORDER BY court_no ASC";
            values.push(sport_type);
        }

        const result = await client.query(query, values);

        res.status(200).json({ courts: result.rows });
    } catch (error) {
        console.error("Error: ", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// bookings
app.post("/bookings", async (req, res) => {
    const { user_id, court_id, booking_date, start_time, end_time } = req.body;
    const client = await pool.connect();
    try {
        // All required field are provided
        if (!user_id || !court_id || !booking_date || !start_time || !end_time) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        // Check if user exists
        const userExists = await client.query(
            "SELECT id FROM users WHERE id = $1",
            [user_id],
        );
        if (userExists.rows.length === 0) {
            return res.status(404).json({ error: "User does not exist." });
        }

        // Check if court available
        const courtAvailable = await client.query(
            `SELECT id FROM courts WHERE id = $1`,
            [court_id],
        );
        if (courtAvailable.rows.length === 0) {
            return res.status(404).json({ error: "Court not found" });
        }

        // Check for double booking
        const doubleBook = await client.query(
            "SELECT * FROM bookings WHERE court_id = $1 AND booking_date = $2 AND NOT (end_time <= $3 OR start_time >= $4)",
            [court_id, booking_date, start_time, end_time],
        );
        if (doubleBook.rows.length > 0) {
            return res
                .status(400)
                .json({ error: "Court already booked for this time slot." });
        }

        // Create a booking
        const result = await client.query(
            "INSERT INTO bookings (user_id, court_id, booking_date, start_time, end_time) VALUES ($1, $2, $3, $4, $5) RETURNING *",
            [user_id, court_id, booking_date, start_time, end_time],
        );
        res
            .status(201)
            .json({ message: "Booking successful", booking: result.rows[0] });
    } catch (error) {
        console.error("Error creating booking: ", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// Create user if not exist (Firebase Auth integration)
app.post("/users", async (req, res) => {
    const { id, name, email } = req.body;

    if (!id || !email) {
        return res
            .status(400)
            .json({ error: "Missing required fields (id, email)" });
    }

    const client = await pool.connect();
    try {
        // Check if user already exists
        const existingUser = await client.query(
            "SELECT * FROM users WHERE id = $1",
            [id],
        );

        if (existingUser.rows.length > 0) {
            return res.json({
                message: "User already exists",
                user: existingUser.rows[0],
            });
        }

        // Insert new user
        const newUser = await client.query(
            "INSERT INTO users (id, name, email) VALUES ($1, $2, $3) RETURNING *",
            [id, name, email],
        );

        res.status(201).json({ message: "User added", user: newUser.rows[0] });
    } catch (error) {
        console.error("Error adding user:", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// Filter bookings by user_id or court_id
app.get("/bookings", async (req, res) => {
    const { user_id, court_id } = req.query;
    const client = await pool.connect();
    try {
        let query =
            "SELECT b.id, b.user_id, b.court_id, TO CHAR(b.booking_date,'YYY-MM-DD') AS booking_date, b.start_time, b.end_time FROM bookings b";
        const values = [];

        if (user_id) {
            query += ` WHERE b.user_id = $1`;
            values.push(user_id);
        } else if (court_id) {
            query += ` WHERE b.court_id = $1`;
            values.push(court_id);
        }

        query += ` ORDER BY b.booking_date ASC`;

        const result = await client.query(query, values);
        res.status(200).json({ bookings: result.rows });
    } catch (error) {
        console.error("Error fetching bookings:", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// get all bookings for a user
app.get("/bookings/currentUser/:id", async (req, res) => {
    const { id } = req.params;
    console.log("➡️ Fetching bookings for user:", id);
    const client = await pool.connect();

    try {
        const result = await client.query(
            `SELECT b.id, b.booking_date, b.start_time, b.end_time, c.sport_type, c.court_no
       FROM bookings b JOIN courts c 
       ON b.court_id = c.id
       WHERE b.user_id = $1
       ORDER BY b.booking_date DESC, b.start_time ASC`,
            [id],
        );

        res.json(result.rows);
    } catch (error) {
        console.error("Error fetching bookings:", error.message);
        res.status(500).json({ error: "Internal server error" });
    } finally {
        client.release();
    }
});

// delete a booking by ID
app.delete("/bookings/:id", async (req, res) => {
    const booking_id = req.params.id;
    const client = await pool.connect();

    try {
        const result = await client.query(
            "DELETE FROM bookings WHERE id = $1 RETURNING *",
            [booking_id],
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: "Booking not found" });
        }

        res.json({
            message: "Booking deleted successfully",
            booking: result.rows[0],
        });
    } catch (error) {
        console.error("Error deleting booking:", error.message);
        res.status(500).json({ error: "Internal server error" });
    } finally {
        client.release();
    }
});

// update booking date/time
app.put("/bookings/:id", async (req, res) => {
    const booking_id = req.params.id;
    const { booking_date, start_time, end_time } = req.body;
    const client = await pool.connect();

    try {
        if (!booking_date || !start_time || !end_time) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const existing = await client.query(
            "SELECT id FROM bookings WHERE id = $1",
            [booking_id],
        );

        if (existing.rows.length === 0) {
            return res.status(404).json({ error: "Booking not found" });
        }

        const result = await client.query(
            `UPDATE bookings
         SET booking_date = $1, start_time = $2, end_time = $3
         WHERE id = $4
         RETURNING id, booking_date, start_time, end_time`,
            [booking_date, start_time, end_time, booking_id],
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Booking not found" });
        }

        const updatedBooking = result.rows[0];

        res.json({
            message: "Booking updated successfully",
            booking: updatedBooking,
        });
    } catch (error) {
        console.error("Error updating booking:", error.message);
        res.status(500).json({ error: "Internal server error" });
    } finally {
        client.release();
    }
});

// Add Stream Chat token endpoint

app.get("/", (req, res) => res.send("Server running!"));

app.get("/stream-token", (req, res) => {
    try {
        const { userId } = req.query;
        const token = getStreamToken(userId);
        res.json({ token });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.listen(3000, () => console.log("✅ Server running on port 3000"));

app.get("/", (req, res) => {
    res.status(200).json({ message: "Booking API is running" });
});

export default app;
