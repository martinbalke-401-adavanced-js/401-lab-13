'use strict';
const Users = require('../models/users-model');
const users = new Users();

const authorization = async (req,res,next) => {
  let user = await users.getFromField({_id: req.user.id});
  if (req.path === '/read-only') req.headers.authorized = user[0].can('read');
  if (req.path === '/create') req.headers.authorized = user[0].can('create');
  if (req.path === '/update/1') req.headers.authorized = user[0].can('update');
  if (req.path === '/delete/1') req.headers.authorized = user[0].can('delete');
  if (req.path === '/super') req.headers.authorized = user[0].can('superuser');
  
  next();

};

module.exports = authorization;