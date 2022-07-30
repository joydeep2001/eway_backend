const passport = require("passport");
const { User } = require("../models/user");
const GoogleStrategy = require("passport-google-oauth2").Strategy;

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id).then((user) => {
    done(null, user);
  });
});
console.log(process.env.NODE_ENV);
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACKURL,
      passReqToCallback: true,
    },
    async function (request, accessToken, refreshToken, profile, done) {
      console.log("Acessing Google Account");
      console.log(profile.email);
      let user = await User.findOne({
        email: profile.email,
      });
      if (user) {
        if (!user.googleId) {
          user.googleId = profile.id;
          await user.save();
        }
        done(null, user);
      } else {
        const Savinguser = new User({
          googleId: profile.id,
          name: profile.displayName,
          email: profile.email,
          isActivated: true,
          username: profile.email,
        });
        user = await User.create(Savinguser);
      }
      return done(null, user);
    }
  )
);

async function authTokenFromGoogleId(req, res) {
  console.log(req.body);

  try {
    const token = jwt.verify(req.body.token, process.env.jwtPrivateKey);
    console.log(token);
    const user = await User.findOne({ googleId: token.googleId });
    if (!user) {
      res.status(400).json({ message: "Invalid userId" });
      return;
    }
    const payload = {
      id: user._id,
      isAdmin: user.admin,
    };
    const authToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET);
    res
      .cookie("auth-token", authToken, {
        httpOnly: true,
        expires: dayjs().add(30, "days").toDate(),
      })
      .json({
        message: user.name + "Well Done ! You are ready to go",
        error: false,
        isAdmin: user.admin,
      });
  } catch (error) {
    console.log(error.message);
    res.status(400).send();
  }
}

module.exports = {
  authTokenFromGoogleId,
};
