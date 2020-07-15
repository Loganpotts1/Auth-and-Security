///////////////////DEPENDENCIES////////////////
require('dotenv').config();
const ejs = require("ejs");
const bodyParser = require("body-parser");
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const bcrypt = require("bcrypt"); --- Encryption Lvl 4
// const md5 = require("md5"); --- Encryption Lvl 3
// const encrypt = require("mongoose-encryption"); --- Encryption Lvl 2

///////////////////SETUP//////////////////////
const app = express();
// const saltRounds = 10; --- Encryption Lvl 4

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

///////////////////MONGO DB//////////////////
mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true,useUnifiedTopology:true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]}); --- Encryption Lvl 2
const User = mongoose.model("user", userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
///////////////////ROUTES////////////////////
app.route("/")
.get(function(req,res){
  res.render("home");
})
;

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});
app.route("/login")
.get(function(req,res){
  res.render("login");
})
.post(function(req,res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
  // User.findOne({                                                                               ]
  //   email: req.body.username                                                                   |
  // }, function(err, foundUser){                                                                 |
  //   if (foundUser){                                                                            |
  //     bcrypt.compare(req.body.password, foundUser.password, function(err, result){             |
  //       if (result === true){ res.render("secrets")} else{ res.send("Incorrect Password.")};   | --- Encryption Lvl 4
  //     });                                                                                      |
  //   } else{                                                                                    |
  //     res.send("Wrong email/password.");                                                       |
  //   }                                                                                          |
  // });                                                                                          ]
})
;

app.route("/logout")
.get(function(req, res){
  req.logout();
  res.redirect("/");
})
;

app.route("/register")
.get(function(req,res){
  res.render("register");
})
.post(function(req,res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash){                           ]
  //   const newUser = new User({                                                              |
  //     email: req.body.username,                                                             |
  //     password: hash                                                                        |
  //   });                                                                                     |
  //   newUser.save(function(err){                                                             |
  //     if (!err){                                                                            | --- Encryption Lvl 4
  //       res.render("secrets");                                                              |
  //     } else{                                                                               |
  //       console.log(err);                                                                   |
  //     }                                                                                     |
  //   });                                                                                     |
  // });                                                                                       ]
})
;

app.route("/secrets")
.get(function(req,res){
  if (req.isAuthenticated()){
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
})
;

///////////////////PORT LISTEN//////////////
app.listen(3000, function(){
  console.log("Firing all cannons on port 3000!");
});
