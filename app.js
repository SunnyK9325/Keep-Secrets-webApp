require('dotenv').config()
const express = require("express");
const mongoose = require("mongoose");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended:true}));

// Initializing session middleware in an Express application with following options
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());


// mongoose.connect("mongodb+srv://sunny9325:brago9325@cluster0.legztwk.mongodb.net/?retryWrites=true&w=majority/keepSecretsDB", {useNewUrlParser:true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// it's going to work for all different strategies not just for the local strategy.
passport.serializeUser(function(user, done) {
    done(null, user);
  });
 
passport.deserializeUser(function(user, done) {
    done(null, user);
});

// gonna work for only local strategy
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //! From GitHub Issues because of G+ Deprecation 
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, (err, user) => {
    //   console.log(profile);
      return cb(err, user);
    });
  }
));

//=========================================== "/" route
app.get("/", function(req, res){
    res.render("home");
});

// login route

app.route("/login")

.get(function(req, res){
    res.render("login");
})

.post(function(req, res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if(err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});


// register route

app.route("/register")

.get(function(req, res){
    res.render("register");
})

.post(function(req, res) {
    
    User.register({username: req.body.username}, req.body.password)
    .then(()=>{
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
        });
    })
    .catch((err)=>{
        // console.log(err);
        res.send("<h1>User with the given username is already registered</h1>");
    });
});


// Google authentication

app.get("/auth/google", 
passport.authenticate("google", {scope: ["profile"]}));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }), (req, res)=> {
    // Successful authentication, redirect secrets page.
    res.redirect("/secrets");
  });


// secrets route

app.get("/secrets", function(req, res) {
    User.find({secret: {$ne:null}})
    .then((foundUsers)=>{
        res.render("secrets", {userWithSecrets: foundUsers});
    })
    .catch((err)=>{
        console.log(err);
    });
});

// logout route

app.get("/logout", function(req, res){
    req.logOut((err) => {
        if (err) {
            res.send(err);
        } else {
            res.redirect("/");
        }
    });
});

// submit route

app.route("/submit")

.get((req, res)=>{
    if(req.isAuthenticated()) {
        res.render("submit");
    }
    else {
        res.redirect("/login");
    }
})

.post((req, res)=>{
        const submittedSecret = req.body.secret;
        User.findById({_id: req.user._id})
        .then((foundUser)=>{
            if(foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save();
                res.redirect("/secrets");
            }
        })
        .catch((err)=>{
            console.log(err);
        });
});

mongoose.connect(process.env.MONGODB_URI, {useNewUrlParser:true}).then(
app.listen(process.env.PORT || 3000, function() {
    console.log("Server started on port 3000");
  })
);
