import bcrypt from "bcrypt";
import Database from "better-sqlite3";
import cors from "cors";
import express from "express";
import { v4 as uuidv4 } from "uuid";

const app = express();
const SERVER_PORT = 3001;

app.use(cors({ origin: "*" }));
app.use(express.json());

const db = new Database("database.db");

db.exec(
	`
	CREATE TABLE IF NOT EXISTS users (
		uid TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL UNIQUE
	)

	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		uid TEXT NOT NULL,
		message TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (uid) REFERENCES users (uid)
	)
`,
	(err) => {
		err ?? console.error("Error creating users table:", err);
	}
);

const stmtFindUser = db.prepare("SELECT * FROM users WHERE username = ?");
const stmtInsertNewUser = db.prepare(
	"INSERT INTO users (uid, username, password) VALUES (?, ?, ?)"
);
const stmtGetUsernameFromUserId = db.prepare(
	"SELECT username FROM users WHERE uid = ?"
);
const stmtGetUserIdFromUserId = db.prepare(
	"SELECT uid FROM users WHERE uid = ?"
);
const stmtInsertMessages = db.prepare(
	"INSERT INTO messages (uid, message) VALUES (?, ?)"
);
const stmtSelectMessagesFromUser = db.prepare(
	"SELECT * FROM messages WHERE uid = ? ORDER BY timestamp DESC"
);

app.post("/api/signup", async (req, res) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res
			.status(400)
			.json({ error: "Username and password are required." });
	}

	try {
		if (stmtFindUser.get(username)) {
			return res
				.status(409)
				.json({ error: "Username already exists." });
		}

		const hashedPassword = await bcrypt.hash(password, 10);
		const uid = uuidv4();

		stmtInsertNewUser.run(uid, username, hashedPassword);
		res.status(201).json({ message: "User created successfully." });
	} catch (error) {
		console.error("Error creating user:", error);
		res.status(500).json({ error: "Internal server error." });
	}
});

app.post("/api/login", async (req, res) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res
			.status(400)
			.json({ error: "Username and password are required." });
	}

	const user = stmtFindUser.get(username);
	if (!user) {
		return res
			.status(401)
			.json({ error: "Invalid username or password." });
	}

	const isPasswordValid = await bcrypt.compare(password, user.password);
	if (!isPasswordValid) {
		return res
			.status(401)
			.json({ error: "Invalid username or password." });
	}

	res.status(200).json({ message: "Login successful." });
});

app.get("/api/user/:userId", async (req, res) => {
	const { userId } = req.params;

	stmtGetUsernameFromUserId.get(userId, (err, row) => {
		if (err) {
			console.error("Error fetching user:", err);
			return res
				.status(500)
				.json({ error: "Internal server error." });
		}

		if (!row) {
			return res.status(404).json({ error: "User not found." });
		}

		res.status(200).json({ username: row.username });
	});
});

app.get("/api/send-message", async (req, res) => {
	const { recipientId, message } = req.body;

	if (!recipientId || !message) {
		return res
			.status(400)
			.json({ error: "Recipient ID and message are required." });
	}

	stmtGetUserIdFromUserId.get(recipientId, (err, row) => {
		if (err) {
			console.error("Error fetching recipient:", err);
			return res
				.status(500)
				.json({ error: "Internal server error." });
		}

		if (!row) {
			return res.status(404).json({ error: "Recipient not found." });
		}

		stmtInsertMessages.run(recipientId, message);
		res.status(201).json({ message: "Message sent successfully." });
	});
});

app.get("/api/messages/:userId", async (req, res) => {
	const { userId } = req.params;

	const messages = stmtSelectMessagesFromUser.all(userId);
	if (!messages.length) {
		return res
			.status(404)
			.json({ error: "No messages found for this user." });
	}

	res.status(200).json(messages);
});

app.listen(SERVER_PORT, () => {
	console.log(`Server is running on port ${SERVER_PORT}`);
});
