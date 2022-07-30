if (process.env.NODE_ENV === "development") {
  require("dotenv").config();
}
console.log("SERVER", process.env.NODE_ENV);

const {
  writeFile,
  getFileExtension,
  compile,
} = require("./controller/compileUtils");
const express = require("express");
const app = express();
const cors = require("cors");
const bodyParser = require("body-parser");
const allUsers = require("./routes/allUsers");
const user = require("./routes/user");
const auth = require("./routes/auth");
const threeDModels = require("./routes/threeDModel");
const config = require("config");
const cookieParser = require("cookie-parser");

if (!config.get("jwtPrivateKey")) {
  console.error("FATAL ERROR: jwt private key is not defined");
  process.exit(1);
}

app.use(
  cors({
    origin: [/\.?engineersway\.in$/, "engineersway.vercel.app"],
    credentials: true,
  })
);
app.use(bodyParser.json());
app.use(cookieParser());

// app.get("/", (req, res) => {
//   console.log("response recieved");
//   res.json("Port working");
// });
app.post("/api/compile", async (req, res) => {
  let fileName = `test.${getFileExtension(req.body.language)}`;
  await writeFile(fileName, req.body.code);
  let result = await compile(fileName, req.body.language);
  res.json(result);
});

app.use("/user", user);
app.use("/auth", auth);
app.use("/3dmodels", threeDModels);
app.use("/allUsers", allUsers);

// if (process.env.NODE_ENV == "production") {
//   app.use(express.static("./client/build"));
//   const path = require("path");

//   app.get("*", (req, res) => {
//     res.sendFile(path.resolve(__dirname, "client", "build", "index.html"));
//   });
// }

app.listen(process.env.PORT || 3001);
