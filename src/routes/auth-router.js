'use strict';

const express = require('express');
const router = express.Router();

const Users = require('../models/users-model.js');
const users = new Users();
const auth = require('../middleware/auth.js');
const err401 = require('../middleware/401.js');

/**
 * @route POST /signup
 * This route creates a new user in our database
 * @param {string}  username.body.required   We need a username in order to create a user
 * @param {string}  password.body.required   We need a password in order to create a user
 * @returns {string} 200 - The Bearer token
 */
router.post('/signup', async (req, res, next) => {
  try {
    let user = await users.create(req.body);
    let token = 'Bearer ' + user.generateToken();

    res.status(200).json({ token: token });
  } catch (e) {
    next(e);
  }
});

/**
 * @route POST /signin
 * This route authenticates and signs in a user. We first run the middleware auth, and for auth we have some catching error middleware, and then we reach the route endpoint
 * @param {string}   authorization.headers.required   We need a basicAuth string in req.headers.authorization. This is a base64 encoding of the username and password for the user
 * @security basicAuth
 * @returns {string} 200 - The Bearer token
 */
router.post('/signin', auth, err401, (req, res, next) => {
  res.status(200).json({ token: req.token });
});

module.exports = router;
