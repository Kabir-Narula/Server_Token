const express = require('express');
const cors = require("cors");
const dotenv = require("dotenv");
const passport = require('passport');
const jwt = require('jsonwebtoken');

// Assuming you have this file set up as per the assignment instructions.
require('./config/passport')(passport);  

dotenv.config();
const userService = require("./user-service.js");
const app = express();

const HTTP_PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(cors());
app.use(passport.initialize());

// Register route
app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
    .then(msg => res.json({ "message": msg }))
    .catch(msg => res.status(422).json({ "message": msg }));
});

// Login route with JWT token generation
app.post("/api/user/login", (req, res) => {
    userService.checkUser(req.body)
    .then(user => {
        const payload = {
            _id: user._id,
            userName: user.userName
        };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }); // Token expires in 24 hours
        res.json({ "message": "login successful", "token": token });
    })
    .catch(msg => res.status(422).json({ "message": msg }));
});

// Middleware to secure routes
const requireAuth = passport.authenticate('jwt', { session: false });

// Secure route examples
app.get("/api/user/favourites", requireAuth, (req, res) => {
    userService.getFavourites(req.user._id)
    .then(data => res.json(data))
    .catch(msg => res.status(422).json({ error: msg }));
});

app.put("/api/user/favourites/:id", requireAuth, (req, res) => {
    userService.addFavourite(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(msg => res.status(422).json({ error: msg }));
});

app.delete("/api/user/favourites/:id", requireAuth, (req, res) => {
    userService.removeFavourite(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(msg => res.status(422).json({ error: msg }));
});

app.get("/api/user/history", requireAuth, (req, res) => {
    userService.getHistory(req.user._id)
    .then(data => res.json(data))
    .catch(msg => res.status(422).json({ error: msg }));
});

app.put("/api/user/history/:id", requireAuth, (req, res) => {
    userService.addHistory(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(msg => res.status(422).json({ error: msg }));
});

app.delete("/api/user/history/:id", requireAuth, (req, res) => {
    userService.removeHistory(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(msg => res.status(422).json({ error: msg }));
});

// Connect to user service and start server
userService.connect().then(() => {
    app.listen(HTTP_PORT, () => {
        console.log(`API listening on: ${HTTP_PORT}`);
    });
}).catch(err => {
    console.log("unable to start the server: ", err);
    process.exit();
});
