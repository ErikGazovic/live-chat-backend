import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import { Strategy } from "passport-local";
import passport from "passport";
import env from "dotenv";

import pkg from "pg";
import cors from "cors";
import http from "http";
import { Server } from "socket.io";

const PORT = 3001;
const app = express();
const saltRounds = 6;
app.use(
  cors({
    origin: ["http://live-chat-itlion.s3-website.eu-north-1.amazonaws.com", "http://localhost:5173"],
    methods: ["GET", "POST"],
  })
);

env.config();

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ["http://live-chat-itlion.s3-website.eu-north-1.amazonaws.com", "http://localhost:5173"],
    methods: ["GET", "POST"],
  },
});
console.log(process.env.DATABASE_URL);
const {Pool} = pkg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    require: true,              // Enforce SSL
    rejectUnauthorized: false,  // Render uses self-signed certs
  },
});



async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(40),
      email VARCHAR(100),
      password VARCHAR(200)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      group_id INTEGER NOT NULL,
      username VARCHAR(100) NOT NULL,
      sender_id VARCHAR(100),
      text TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("Tables created...");
}

createTables();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("send_message", async (data) => {
    const { group_id, username, sender_id, text } = data;

    try {
      const result = await pool.query(
        "INSERT INTO messages (group_id, username, sender_id, text) VALUES ($1, $2, $3, $4) RETURNING *",
        [group_id, username, sender_id, text]
      );

      const res = await pool.query("SELECT * FROM messages WHERE group_id = $1", [
        group_id,
      ]);
      const resCount = res.rowCount;
      if (resCount > 1000) {
        await pool.query(
          `
  WITH oldest AS (
    SELECT id
    FROM messages
    WHERE group_id = $1
    ORDER BY timestamp ASC
    LIMIT 500
  )
  DELETE FROM messages
  WHERE id IN (SELECT id FROM oldest)
  AND (SELECT COUNT(*) FROM messages WHERE group_id = $1) > 1000
`,
          [group_id]
        );
        console.log("DELETED LAST 5 MESSAGES");
      }

      console.log("Received message:", result.rows[0]);
      io.emit("receive_message", result.rows[0]);
    } catch (err) {
      console.error(err);
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

app.get("/get-messages/:group_id", async (req, res) => {
  const groupID = req.params.group_id;
  try {
    const result = await pool.query(
      "SELECT * FROM messages WHERE group_id = $1 ORDER BY timestamp DESC",
      [groupID]
    );
    res.json(result.rows);
  } catch {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/register", async (req, res) => {
  const { username, email, password, repeatedPassword } = req.body;
  let passwordMessage = "";
  try {
    const checkResultEmail = await pool.query(
      "SELECT * FROM chat_users WHERE email = $1",
      [email]
    );
    const checkResultUsername = await pool.query(
      "SELECT * FROM chat_users WHERE username = $1",
      [username]
    );
    if (checkResultEmail.rows.length > 0) {
      let emailMessage = "Používateľ s týmto emailom už existuje";
      return res.json({
        success: false,
        errorType: "email",
        errorMessage: emailMessage,
        received: { username, email, password, repeatedPassword },
        reply: `Wrong credentials on ${email}`,
      });
    } else if (username.length < 3) {
      let nameMessage = "Používateľské meno je moc krátke";
      return res.json({
        success: false,
        errorType: "username",
        errorMessage: nameMessage,
        received: { username, email, password, repeatedPassword },
        reply: `Wrong credentials on ${username}`,
      });
    } else if (checkResultUsername.rows.length > 0) {
      let nameMessage = "Používateľ s týmto menom už existuje";
      return res.json({
        success: false,
        errorType: "username",
        errorMessage: nameMessage,
        received: { username, email, password, repeatedPassword },
        reply: `Wrong credentials on ${username}`,
      });
    } else if (checkRegisterPassword(password, repeatedPassword)[0] == false) {
      passwordMessage = checkRegisterPassword(password, repeatedPassword)[1];
      return res.json({
        success: false,
        errorType: "password",
        errorMessage: passwordMessage,
        received: { username, email, password, repeatedPassword },
        reply: `Wrong credentials on ${password}`,
      });
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          res.send(err);
        } else {
          const result = await pool.query(
            "INSERT INTO chat_users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
            [username, email, hash]
          );
          console.log(result.rows[0].username);
          if (result.rows[0].username) {
            return res.json({
              success: true,
              errorType: null,
              message: "Účet bol úspešne vytvorený",
              received: { username, email, password, repeatedPassword },
              reply: `Successfully registered on credentials ${
                (username, email, password, repeatedPassword)
              }`,
            });
          } else {
            return res.json({
              success: false,
              received: { username, email, password, repeatedPassword },
              reply: `Something went wrong`,
            });
          }
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", (req, res) => {
  passport.authenticate("local", (err, user, options) => {
    if (user) {
      return res.json({
        success: true,
        errorType: null,
        received: user,
        message: "Successfully logged in",
        reply: `User ${user.username} was logged in on credentials ${
          (user.email, user.password)
        }`,
      });
    } else {
      if (options.message === "Nesprávne heslo") {
        return res.json({
          success: false,
          errorType: "password",
          received: user,
          errorMessage: options.message,
          reply: `User ${user.username} was logged in on credentials ${
            (user.email, user.password)
          }`,
        });
      } else {
        return res.json({
          success: false,
          errorType: "email",
          received: user,
          errorMessage: options.message,
          reply: `User ${user.username} was logged in on credentials ${
            (user.email, user.password)
          }`,
        });
      }
    }
  })(req, res);
});

passport.use(
  new Strategy(
    { usernameField: "email", passwordField: "password" },
    async function verify(email, password, cb) {
      try {
        const checkResultEmail = await pool.query(
          "SELECT * FROM chat_users WHERE email = $1",
          [email]
        );

        if (checkResultEmail.rows.length > 0) {
          const user = checkResultEmail.rows[0];
          const storedHashedPassword = user.password;
          bcrypt.compare(password, storedHashedPassword, (err, result) => {
            if (err) {
              return cb(err);
            } else {
              if (result) {
                return cb(null, user);
              } else {
                return cb(null, false, { message: "Nesprávne heslo" });
              }
            }
          });
        } else {
          return cb(null, false, {
            message: "Používateľ s týmto emailom neexistuje",
          });
        }
      } catch (err) {
        console.log("error");
        return cb(err);
      }
    }
  )
);

server.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

function checkRegisterPassword(password, reppeatedPassword) {
  const alphabetLowerCase = "abcdefghijklmnopqrstuvwxyz".split("");
  let lowerCaseCount = 0;
  const alphabetUpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");
  let upperCaseCount = 0;
  const numbers = "1234567890".split("");
  let numbersCount = 0;

  for (var i = 0; i < alphabetLowerCase.length; i++) {
    if (password.includes(alphabetLowerCase[i])) {
      lowerCaseCount++;
      if (lowerCaseCount > 0) {
        break;
      }
    }
  }

  for (var i = 0; i < alphabetUpperCase.length; i++) {
    if (password.includes(alphabetUpperCase[i])) {
      upperCaseCount++;
      if (upperCaseCount > 0) {
        break;
      }
    }
  }

  for (var i = 0; i < numbers.length; i++) {
    if (password.includes(numbers[i])) {
      numbersCount++;
      if (numbersCount > 0) {
        break;
      }
    }
  }

  if (password != reppeatedPassword) {
    let passwordMessage = "Heslá sa nezhodujú";
    return [false, passwordMessage];
  } else if (password.length < 6) {
    let passwordMessage = "Heslo je moc krátke";
    return [false, passwordMessage];
  } else if (lowerCaseCount < 1) {
    let passwordMessage = "Heslo musí obsahovať aspoň jeden malý charakter";
    return [false, passwordMessage];
  } else if (upperCaseCount < 1) {
    let passwordMessage = "Heslo musí obsahovať aspoň jeden veľký charakter";
    return [false, passwordMessage];
  } else if (numbersCount < 1) {
    let passwordMessage = "Heslo musí obsahovať aspoň jedno číslo";
    return [false, passwordMessage];
  } else {
    return true;
  }
}

