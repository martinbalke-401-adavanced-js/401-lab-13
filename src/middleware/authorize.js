'use strict';
const Users = require('../models/users-model');
const users = new Users();

/**
 * Function authorization is a middleware that checks if a user is authorized to use a specific route
 * @param {Object} req - Information about the request passing through this function
 * @param {Function} next - The next function that hands off the request object to the next middleware
 */
const authorization = async (req,res,next) => {
  //Get the user from the request id
  let user = await users.getFromField({_id: req.user.id});
  //Depending on the route check to see if the use has the permissions necessary and set that as a header
  if (req.path === '/read-only') req.headers.authorized = user[0].can('read');
  if (req.path === '/create') req.headers.authorized = user[0].can('create');
  if (req.path === '/update/1') req.headers.authorized = user[0].can('update');
  if (req.path === '/delete/1') req.headers.authorized = user[0].can('delete');
  if (req.path === '/super') req.headers.authorized = user[0].can('superuser');
  next();

};

module.exports = authorization;