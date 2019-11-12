'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const roles = require('./roles-schema');

/**
 * The schema definition for a user record
 * @type {mongoose.Schema}
 */
const users = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String },
  role: { type: String, default: 'user', enum: ['admin', 'editor', 'user'] },
});

// === TODO: Implement a virtual connection between users and roles, so that we can access
// === user capabilities easily =====
// === Utilize virtuals and the populate() mongoose method ===
users.virtual('permissions', {
  ref: 'roles',
  localField: 'role',
  foreignField: 'role',
  justOne: false,
});


users.post('findOne', async function (user) {
  await user.populate('permissions');
});

users.methods.can = function(string) {
  if(this.permissions.includes(string)) return true;
  return false;
};

/**
 * Pre middleware which converts a string password into a hashed password before every save to MongoDB
 */
users.pre('save', async function() {
  this.password = await bcrypt.hash(this.password, 10);
});

/**
 * This function does a simple authentication by hashing the inputted password, and comparing it against an existing hashed password.
 * Because this is a statics function, `this` refers to the entire Users model
 * @param  {object}     auth    The authentication credentials, containing a key username and password
 * @return {Promise<object>}    A record of a user that was successfully authenticated against the credentials
 */
users.statics.authenticateBasic = async function(auth) {
  let query = { username: auth.username };
  let foundUser = await this.findOne(query);
  let isSamePassword = null;
  console.log(foundUser);

  if (foundUser)
    isSamePassword = await bcrypt.compare(auth.password, foundUser.password);

  if (isSamePassword) return foundUser;
  else return null;
};

/**
 * This function generates a JSON Web Token from a user's id, role and the application's secret
 * Because this is a methods function, `this` refers to an individual user record
 * @param {string} timeout - The amount of time for a token to expire in
 * @return {string} The generated jwt token
 */

users.methods.generateToken = function(timeout) {
  let secret = process.env.SECRET || 'this-is-my-secret';
  let data = {
    id: this._id,
  };
  return jwt.sign(data, secret, {expiresIn: timeout});
};

/**
 * Exporting a mongoose model generated from the above schema, statics, methods and middleware
 * @type {mongoose model}
 */
module.exports = mongoose.model('users', users);
