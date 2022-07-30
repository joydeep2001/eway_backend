const config = require("config");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const _ = require("lodash");
const { User } = require("../models/user");
const mongoose = require("mongoose");
const express = require("express");
const router = express.Router();
const Joi = require("joi");
const { authTokenFromGoogleId } = require("../controller/googleSignup");
const passport = require("passport");

function validate(user) {
  const schema = Joi.object({
    username: Joi.string().min(3).max(16).required(),
    password: Joi.string().min(5).max(255).required(),
  });
  return schema.validate(user);
}
router.post("/", async (req, res) => {
  const { error } = validate(req.body);
  if (error) return res.status(400).send({ message: error.details[0].message });
  let user = await User.findOne({ username: req.body.username });

  if (!user)
    return res.status(400).send({ message: "Invalid username or password" });

  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword)
    return res.status(400).send({ message: "Invalid username or password" });
  const token = user.generateAuthToken();
  res.status(200).send({ token });
});
router.get("/activate/:token", async (req, res) => {
  jwt.verify(req.params.token, config.get("jwtPrivateKey"), async (err, id) => {
    if (err) return res.status(401).send("<h1>Invalid token</h1>");
    let user = await User.findOne({ _id: id });
    if (!user) return res.status(404).send("<h1>User not found</h1>");
    user.isActivated = true;
    user.save();
    res
      .status(200)
      .send(
        `<h2>account activated successfully<a href=${config.get(
          "frontEndURL"
        )}/login>Click Here to Login</a></h2>`
      );
  });
});

router.post("/authtokenFromGoogleId/", authTokenFromGoogleId);
router.get(
  "/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);

router.get(
  "/google/callback/",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    console.log(req.user.googleId);
    const payload = {
      googleId: req.user.googleId,
    };
    const token = jwt.sign(payload, process.env.jwtPrivateKey);
    res.redirect("http://localhost:3000/Redirect/?token=" + token);
    console.log("call back");
  }
);

module.exports = router;
