require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const session = require("express-session");
const passport = require("passport");
const passportMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const server = express();

const schema = mongoose.Schema;

server.use(express.static("public"));
server.set("view engine", "ejs");
server.use(bodyParser.urlencoded({ extended: true }));

//here we are setting session
server.use(
  session({
    secret: "mySecretLife.",
    saveUninitialized: false,
    resave: false,
  })
);
//here we are setting passport inorder to maintain the session
server.use(passport.initialize());
server.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userData", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.set("useCreateIndex", true);

const userSchema = new schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportMongoose);
userSchema.plugin(findOrCreate);

//used for encrypting the code and saving only the hashed password
// userSchema.plugin(encrypt, {
//   secret: process.env.SECRET,
//   encryptedFields: ["password"],
// });

//here we are hashing and storing it in our database - this is encryption
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:5000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

server.get("/", (req, res) => {
  res.render("home");
});

server.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

server.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  }
);

server.get("/register", (req, res) => {
  res.render("register");
});

server.get("/login", (req, res) => {
  res.render("login");
});

server.get("/logout", (req, res) => {
  req.logOut();
  res.redirect("/");
});

server.get("/secrets", (req, res) => {
  User.find({"secret" : {$ne : null}},(err, foundUser) => {
if(err){
console.log(err);
} else {
  if(foundUser){
    res.render("secrets", {userWithSecrets : foundUser.secret})
  }
}
  });
});

server.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

server.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  User.findById(req.body.id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      }
    }
  });
});

//here we are using HASHING by using md5
server.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    }
  );
});

server.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.logIn(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("secrets");
      });
    }
  });
});

server.listen(5000, () => {
  console.log("server runs on port 5000");
});
