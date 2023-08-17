const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const {
    authenticateJWT,
    ensureLoggedIn,
    ensureCorrectUser,
} = require("../middleware/auth");
const User = require("../models/user");
const { SECRET_KEY } = require("../config");
const jwt = require("jsonwebtoken");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async (req, res, next) => {
    try {
        const { username, password } = req.body;
        if (await User.authenticate(username, password)) {
            User.updateLoginTimestamp(username);
            let token = jwt.sign({ username }, SECRET_KEY);
            return res.json({ token });
        }
        throw new ExpressError("Invalid username/password", 400);
    } catch (e) {
        return next(e);
    }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async (req, res, next) => {
    try {
        const user = await User.register(req.body);
        const { username } = user.username;
        let token = jwt.sign({ username }, SECRET_KEY);
        User.updateLoginTimestamp(username);
        return res.json({ token });
    } catch (e) {
        next(e);
    }
});
module.exports = router;
