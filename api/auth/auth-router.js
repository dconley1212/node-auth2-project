const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require("../users/users-model");
const { BCRYPT_ROUNDS } = require("../secrets/index");

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET, options);
}

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try {
    const { username, password, role_name } = req.body;
    const hash = bcrypt.hashSync(password, BCRYPT_ROUNDS);
    const user = { username, password: hash, role_name };
    const createdUser = await User.add(user);
    res.status(201).json(createdUser[0]);
  } catch (err) {
    next(err);
  }
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  let { username, password } = req.body;

  User.findBy({ username })
    .then(([filteredUser]) => {
      if (filteredUser && bcrypt.compareSync(password, filteredUser.password)) {
        const token = buildToken(filteredUser);
        res.status(200).json({
          message: `${filteredUser.username} is back`,
          token: token,
        });
      } else {
        next({ status: 401, message: "Invalid credentials" });
      }
    })
    .catch(next);
});

module.exports = router;
