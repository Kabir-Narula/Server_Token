const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');

dotenv.config();
const userService = require('./user-service.js');

const app = express();
const HTTP_PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(cors());
app.use(passport.initialize());

const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
};

passport.use(new JwtStrategy(jwtOptions, async (jwtPayload, done) => {
    try {
        const user = await userService.findUserById(jwtPayload._id);
        return user ? done(null, user) : done(null, false);
    } catch (error) {
        done(error, false);
    }
}));

// Registration endpoint with detailed error logging
// app.post("/api/user/register", async (req, res) => {
//     try {
//         const hashedPassword = await bcrypt.hash(req.body.password, 10);
//         const user = await userService.registerUser({ ...req.body, password: hashedPassword });
//         res.status(201).json({ message: "User registered successfully", userId: user._id });
//     } catch (error) {
//         console.error("Error registering user", error.response ? error.response.data : error);
//         res.status(500).json({ message: "Error registering user", detail: error.toString() });
//     }
// });

app.post("/api/user/register", (req, res) => {
    userService
      .registerUser(req.body)
      .then((msg) => res.json({ message: msg }))
      .catch((msg) => res.status(422).json({ message: msg }));
  });
  

// Login endpoint with detailed error information
app.post("/api/user/login", async (req, res) => {
    try {
        // Extract userName and password from the request body
        const { userName, password } = req.body;
        
        // Use the user service to authenticate the user
        const user = await userService.checkUser({ userName, password });

        // If authentication is successful, generate a JWT
        const payload = { _id: user._id, userName: user.userName };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });

        // Return the token as a Bearer token
        res.json({ message: "Login successful", token: `Bearer ${token}` });
    } catch (error) {
        // Handle errors during login
        console.error("Error logging in:", error);
        if (error.message.includes("Unable to find user")) {
            res.status(401).json({ message: "Login failed: User not found" });
        } else if (error.message.includes("Incorrect password")) {
            res.status(401).json({ message: "Login failed: Incorrect password" });
        } else {
            res.status(500).json({ message: "Server error", detail: error.toString() });
        }
    }
});


// Example of a secured route: Get user's favorites
app.get("/api/user/favourites", passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const favourites = await userService.getFavourites(req.user._id);
        res.json(favourites);
    } catch (error) {
        res.status(500).json({ message: "Error getting favourites", error: error.message });
    }
});

// Add a favorite item for the user
app.put("/api/user/favourites/:id", passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        await userService.addFavourite(req.user._id, req.params.id);
        res.json({ message: "Favourite added successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error adding favourite", error: error.message });
    }
});

// Remove a favorite item for the user
app.delete("/api/user/favourites/:id", passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        await userService.removeFavourite(req.user._id, req.params.id);
        res.json({ message: "Favourite removed successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error removing favourite", error: error.message });
    }
});

// Get user's history
app.get("/api/user/history", passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const history = await userService.getHistory(req.user._id);
        res.json(history);
    } catch (error) {
        res.status(500).json({ message: "Error getting history", error: error.message });
    }
});

// Add an item to the user's history
app.put("/api/user/history/:id", passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        await userService.addHistory(req.user._id, req.params.id);
        res.json({ message: "History item added successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error adding history item", error: error.message });
    }
});

app.delete("/api/user/history/:id", passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        await userService.removeHistory(req.user._id, req.params.id);
        res.json({ message: "History item removed successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error removing history item", error: error.message });
    }
});

userService.connect().then(() => {
    app.listen(HTTP_PORT, () => {
        console.log(`Server running on port ${HTTP_PORT}`);
    });
}).catch((err) => {
    console.error("Unable to start the server:", err);
    process.exit(1);
});
