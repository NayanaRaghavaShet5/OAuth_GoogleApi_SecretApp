require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const server = express();

const schema = mongoose.Schema;

server.use(express.static("public"));
server.set("view engine", "ejs");
server.use(bodyParser.urlencoded({ extended: true }));

server.get("/", (req, res) => {
  res.render("home");
});

server.get("/register", (req, res) => {
  res.render("register");
});

server.get("/login", (req, res) => {
  res.render("login");
});

mongoose.connect("mongodb://localhost:27017/userData", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new schema({
  email: String,
  password: String,
  salt: String,
});

//used for encrypting the code and saving only the hashed password
// userSchema.plugin(encrypt, {
//   secret: process.env.SECRET,
//   encryptedFields: ["password"],
// });

//here we are hashing and storing it in our database - this is encryption
const User = new mongoose.model("User", userSchema);

//here we are using HASHING by using md5
server.post("/register", (req, res) => {
  bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
    const saveUser = new User({
      email: req.body.username,
      password: hash,
    });
    saveUser.save((err) => {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });
});

server.post("/login", (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  User.findOne({ email: email }, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, (err, result) => {
          if (result === true) res.render("secrets");
        });
      }
    }
  });
});

server.listen(5000, () => {
  console.log("server runs on port 5000");
});
