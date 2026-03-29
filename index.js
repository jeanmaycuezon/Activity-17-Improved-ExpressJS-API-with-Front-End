const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const nodemailer = require("nodemailer");

const db = require("./config/db");

const app = express();
const SECRET_KEY = "securekey";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static("uploads"));

//  SERVE FRONTEND 
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

// ================= MULTER =================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

// ================= EMAIL =================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "jnmycuezon7@gmail.com",
    pass: "password0906"
  }
});

// ================= REGISTER =================
app.post("/register", upload.single("profile_pic"), async (req, res) => {
  const { name, email, password } = req.body;
  const file = req.file ? req.file.filename : null;

  try {
    const hashed = await bcrypt.hash(password, 10);
    const token = Math.random().toString(36).substring(2);

    db.query(
      "INSERT INTO users (name,email,password,verification_token,profile_pic) VALUES (?,?,?,?,?)",
      [name, email, hashed, token, file],
      async (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.json({ success:false, message:"Email already exists" });
          }
          return res.json({ success:false, message:"Database error" });
        }

        const link = `${BASE_URL}/verify/${token}`;

        await transporter.sendMail({
          to: email,
          subject: "Verify Account",
          html: `<a href="${link}">Verify Account</a>`
        });

        res.json({ success:true, message:"Check your email for verification" });
      }
    );
  } catch {
    res.json({ success:false, message:"Server error" });
  }
});

// ================= VERIFY =================
app.get("/verify/:token", (req, res) => {
  db.query(
    "UPDATE users SET is_verified=1 WHERE verification_token=?",
    [req.params.token],
    (err, result) => {
      if (result.affectedRows === 0) return res.send("Invalid link");

      res.send("<h2>Account Verified</h2>");
    }
  );
});

// ================= LOGIN (2FA) =================
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, r) => {
    if (r.length === 0) return res.json({ success:false, message:"User not found" });

    const user = r[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.json({ success:false, message:"Wrong password" });

    const token = Math.random().toString(36).substring(2);

    db.query("UPDATE users SET login_token=? WHERE id=?", [token, user.id]);

    const link = `${BASE_URL}/verify-login/${token}`;

    await transporter.sendMail({
      to: email,
      subject: "Login Verification",
      html: `<a href="${link}">Verify Login</a>`
    });

    res.json({ success:true, message:"Check email to login" });
  });
});

// ================= VERIFY LOGIN =================
app.get("/verify-login/:token", (req, res) => {
  db.query("SELECT * FROM users WHERE login_token=?", [req.params.token], (err, r) => {
    if (r.length === 0) return res.send("Invalid login");

    const user = r[0];

    const jwtToken = jwt.sign(
      { id:user.id, email:user.email },
      SECRET_KEY,
      { expiresIn:"1h" }
    );

    // CLEAR TOKEN AFTER USE
    db.query("UPDATE users SET login_token=NULL WHERE id=?", [user.id]);

    res.redirect(`${BASE_URL}/?token=${jwtToken}`);
  });
});

// ================= FORGOT =================
app.post("/forgot-password", (req, res) => {
  const token = Math.random().toString(36).substring(2);

  db.query(
    "UPDATE users SET reset_token=? WHERE email=?",
    [token, req.body.email],
    async (err, result) => {
      if (result.affectedRows === 0)
        return res.json({ success:false, message:"Email not found" });

      const link = `${BASE_URL}/reset-password/${token}`;

      await transporter.sendMail({
        to: req.body.email,
        subject: "Reset Password",
        html: `<a href="${link}">Reset Password</a>`
      });

      res.json({ success:true, message:"Reset link sent" });
    }
  );
});

// ================= RESET PASSWORD =================
app.get("/reset-password/:token", (req, res) => {
  res.send(`
    <form method="POST" action="/reset-password/${req.params.token}">
      <input name="password" type="password" placeholder="New Password"/>
      <button>Reset</button>
    </form>
  `);
});

app.post("/reset-password/:token", async (req, res) => {
  const hashed = await bcrypt.hash(req.body.password, 10);

  db.query(
    "UPDATE users SET password=?, reset_token=NULL WHERE reset_token=?",
    [hashed, req.params.token],
    (err, result) => {
      if (result.affectedRows === 0) return res.send("Invalid");

      res.send("Password updated");
    }
  );
});

app.post("/logout-request", verifyToken, async (req, res) => {
  const token = Math.random().toString(36).substring(2);

  db.query(
    "UPDATE users SET logout_token=? WHERE id=?",
    [token, req.user.id]
  );

  const link = `${BASE_URL}/logout/${token}`;

  await transporter.sendMail({
    to: req.user.email,
    subject: "Confirm Logout",
    html: `<a href="${link}">Click to confirm logout</a>`
  });

  res.json({ success:true, message:"Logout confirmation sent to email" });
});

app.get("/logout/:token", (req, res) => {
  db.query(
    "SELECT * FROM users WHERE logout_token=?",
    [req.params.token],
    (err, r) => {
      if (r.length === 0) return res.send("Invalid logout link");

      // clear logout token
      db.query("UPDATE users SET logout_token=NULL WHERE id=?", [r[0].id]);

    res.send(`
  <script>
    localStorage.removeItem("token");
    window.location.href = "/";
  </script>
`);
    }
  );
});

// ================= AUTH =================
function verifyToken(req, res, next){
  const token = req.headers.authorization;
  if(!token) return res.send("Denied");

  jwt.verify(token, SECRET_KEY, (err, decoded)=>{
    if(err) return res.send("Invalid");
    req.user = decoded;
    next();
  });
}

// ================= PROFILE =================
app.get("/profile-data", verifyToken, (req, res) => {
  db.query(
    "SELECT id,name,email,profile_pic FROM users WHERE id=?",
    [req.user.id],
    (err, r) => res.json(r[0])
  );
});

// ================= UPDATE PROFILE =================
app.put("/update-profile", verifyToken, upload.single("profile_pic"), (req, res) => {
  const file = req.file;

  if (file) {
    db.query(
      "UPDATE users SET name=?, profile_pic=? WHERE id=?",
      [req.body.name, file.filename, req.user.id]
    );
  } else {
    db.query(
      "UPDATE users SET name=? WHERE id=?",
      [req.body.name, req.user.id]
    );
  }

  res.json({ success:true });
});

// ================= SERVER =================
app.listen(3000, ()=>console.log("Server running on port 3000"));