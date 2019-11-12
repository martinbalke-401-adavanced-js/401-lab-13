'use strict';

const express = require('express');
const router = express.Router();

// TODO: Swagger Comments
// Visible by all clients
router.get('/public', (req, res, next) => {
  res.status(200).json({ valid: true });
});

// === TODO: Define all the routes below ======

// TODO: Swagger Comments
// Visible by logged in clients
router.get('/hidden', (req, res, next) => {});

// TODO: Swagger Comments
// Visible by roles that have the "read" capability
router.get('/read-only', (req, res, next) => {});

// TODO: Swagger Comments
// Accessible by roles that have the "create" capability
router.post('/create', (req, res, next) => {});

// TODO: Swagger Comments
// Accessible by roles that have the "update" capability
router.put('/update/:id', (req, res, next) => {});

// TODO: Swagger Comments
// Accessible by roles that have the "delete" capability
router.delete('/delete/:id', (req, res, next) => {});

// TODO: Swagger Comments
// Visible by roles that have the "superuser" capability
router.get('/super', (req, res, next) => {});

module.exports = router;
