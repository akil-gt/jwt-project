// import express
const express = require("express");

// import cors
const cors = require("cors");

// import bcrypt
const bcrypt = require("bcrypt");

// import jwt
const jwt = require("jsonwebtoken");

// import mysql
const mysql = require("mysql2");

// import dotenv
require("dotenv").config();

// import express 
const app = express();


//MIDDLEWARE


// middleware untuk membaca data JSON dari client (POST/PUT)
app.use(express.json()); 

// middleware untuk mengizinkan akses dari frontend (beda origin)
app.use(cors());


const db = mysql.createConnection({
  host: process.env.DB_HOST,      // ambil dari .env
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// cek koneksi
db.connect((err) => {
  if (err) {
    console.log("Koneksi gagal:", err);
  } else {
    console.log("Database terhubung ✅");
  }
});

// Middleware cek token
const verifyToken = (req, res, next) => {
  // ambil token dari header
  const authHeader = req.headers["authorization"];

  // cek ada token atau tidak
  if (!authHeader) {
    return res.json({ message: "Token tidak ada ❌" });
  }

  // format: Bearer TOKEN
  const token = authHeader.split(" ")[1];

  // verifikasi token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.json({ message: "Token tidak valid ❌" });
    }

    // simpan data user ke request
    req.user = decoded;

    next(); // lanjut ke route berikutnya
  });
};

//-------
// dibawah ini Router
//-------
// API register
app.post("/register", async (req, res) => {
  // ambil data dari request body
  const { username, password } = req.body;

  // untuk tampilan di terminal data masuk
console.log("USERNAME:", username);
console.log("PASSWORD:", password);

  // validasi sederhana
  if (!username || !password) {
    return res.json({ message: "Username dan password wajib diisi" });
  }

  // 🔐 hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // query insert ke database
  const sql = "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)";

  db.query(sql, [username, hashedPassword, false], (err, result) => {
    if (err) {
      console.log(err);
      return res.json({ message: "Gagal register" });
    }

    res.json({message:"Register berhasil ✅"});
  });
});

// jalankan server di port
const PORT = process.env.PORT || 3000;


// API login
app.post("/login", async (req, res) => {
  console.log("API LOGIN KENA 🔐");

  // ambil data dari request
  const { username, password } = req.body;

  // cek ke database
  const sql = "SELECT * FROM users WHERE username = ?";

  db.query(sql, [username], async (err, results) => {
    if (err) {
      console.log("ERROR DB:", err);
      return res.json({ message: "Error server" });
    }

    // kalau user tidak ditemukan
    if (results.length === 0) {
      return res.json({ message: "User tidak ditemukan"});
    }

    const user = results[0];

// compare password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Password salah"});
    }
    // 🔥 buat token JWT
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username
      },
      process.env.JWT_SECRET, // dari .env
      {
        expiresIn: "1h" // token berlaku 1 jam
      }
    );

    console.log("TOKEN:", token);

    // kirim token ke client
    res.json({ message: "Login berhasil ✅",token: token });
  });
});

// route yang butuh login, respon dari dashboard
app.get("/dashboard", verifyToken, (req, res) => {
  res.json({ message: "Selamat datang " + req.user.username + " 🎉" });
});

// untuk menghubungkan port
app.listen(PORT, () => {
  console.log("Server jalan di http://localhost:" + PORT);
});
