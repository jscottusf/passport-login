if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const express = require("express");
const app = express();
const PORT = process.env.PORT || 8080;
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
const exphbs = require("express-handlebars");
app.engine("handlebars", exphbs({ defaultLayout: "main" }));
app.set("view engine", "handlebars");
app.use(express.static("public"));
const bcrypt = require("bcryptjs");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");
const authUtils = require("./utils/auth");
const MongoClient = require("mongodb").MongoClient;
const Strategy = require("passport-local").Strategy;
const ObjectID = require("mongodb").ObjectID;

app.use(flash());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));

//"mongodb+srv://jscottusf:IgPj2uoehQiVellZ@cluster0-giujn.mongodb.net/test?retryWrites=true&w=majority"
//'mongodb:/ / localhost'
MongoClient.connect(
  process.env.DATABASE_URL,
  { useUnifiedTopology: true },
  (err, client) => {
    if (err) {
      throw err;
    }

    const db = client.db("crishipped-users");
    const users = db.collection("users");
    app.locals.users = users;
  }
);

passport.use(
  new Strategy((email, password, done) => {
    app.locals.users.findOne({ email }, (err, user) => {
      if (err) {
        return done(err);
      }

      if (!user) {
        return done(null, false);
      }

      if (user.password != authUtils.hashPassword(password)) {
        return done(null, false);
      }

      return done(null, user);
    });
  })
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser((id, done) => {
  done(null, { id });
});

app.get("/", checkAuthenticated, (req, res) => {
  const users = req.app.locals.users;
  const _id = ObjectID(req.session.passport.user);
  console.log(_id);

  users.findOne({ _id }, (err, results) => {
    if (err || !results) {
      res.render("index", { messages: { error: ["User not found"] } });
    }
    res.render("index", { name: results.name });
  });
});

app.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login");
});

app.post(
  "/login",
  checkNotAuthenticated,
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: "wrong username or password"
  }),
  (req, res, next) => {
    res.redirect("/");
  }
);

app.get("/register", checkNotAuthenticated, (req, res) => {
  res.render("register");
});

app.post("/register", checkNotAuthenticated, (req, res, next) => {
  //const hashedPassword = bcrypt.hash(req.body.password, 10);
  const registrationParams = req.body;
  const users = req.app.locals.users;
  const payload = {
    name: registrationParams.name,
    email: registrationParams.email,
    password: authUtils.hashPassword(registrationParams.password)
  };

  users.insertOne(payload, err => {
    if (err) {
      req.flash("error", "User account already exists");
    } else {
      req.flash("success", "User account registered successfully");
    }
    res.redirect("/login");
  });
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect("/login");
}

app.delete("/logout", (req, res) => {
  req.logOut();
  res.redirect("/login");
});

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

app.listen(PORT, function() {
  console.log("App listening on PORT " + PORT);
});
