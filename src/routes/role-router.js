'use strict';

const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const error403 = require('../middleware/403');
const error401 = require('../middleware/401');
const authorize = require('../middleware/authorize');



// TODO: Swagger Comments
// Visible by all clients
router.get('/public', (req, res, next) => {
  res.status(200).json({ valid: true });
});

router.use(auth);
router.use(error401);




// === TODO: Define all the routes below ======

// TODO: Swagger Comments
// Visible by logged in clients
router.get('/hidden', (req, res, next) => {
  if (req.user && req.user._id) res.status(200).json({ valid: true });
  else next('Forbidden');
});

router.use(authorize);
// TODO: Swagger Comments
// Visible by roles that have the "read" capability
router.get('/read-only', (req, res, next) => {
  if (req.headers.authorized) res.status(200).json({ valid: true });
  else next('Forbidden');
});

// TODO: Swagger Comments
// Accessible by roles that have the "create" capability
router.post('/create', (req, res, next) => {
  if (req.headers.authorized) res.status(200).json({ valid: true });
  else next('Forbidden');
});

// TODO: Swagger Comments
// Accessible by roles that have the "update" capability
router.put('/update/:id', (req, res, next) => {
  if (req.headers.authorized) res.status(200).json({ valid: true });
  else next('Forbidden');
});

// TODO: Swagger Comments
// Accessible by roles that have the "delete" capability
router.delete('/delete/:id', (req, res, next) => {
  if (req.headers.authorized) res.status(200).json({ valid: true });
  else next('Forbidden');
});

// TODO: Swagger Comments
// Visible by roles that have the "superuser" capability
router.get('/super', (req, res, next) => {
  if (req.headers.authorized) res.status(200).json({ valid: true });
  else next('Forbidden');
});

router.use(error403);

module.exports = router;
