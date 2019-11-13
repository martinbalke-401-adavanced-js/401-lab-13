'use strict';

process.env.SECRET = 'test';

const jwt = require('jsonwebtoken');

const Roles = require('../src/auth/roles-model.js');
const server = require('../src/server.js').server;
const supertester = require('./supertester.js');

const mockRequest = supertester.server(server);

let users = {
  admin: {
    username: 'sarah',
    password: 'sarahpassword',
    email: 'sarah@email.com',
    role: 'admin',
  },
  editor: {
    username: 'bill',
    password: 'billpassword',
    email: 'bill@email.com',
    role: 'editor',
  },
  user: {
    username: 'rene',
    password: 'renepassword',
    email: 'rene@email.com',
    role: 'user',
  },
};

let roles = {
  admin: {
    role: 'admin',
    capabilities: ['create', 'read', 'update', 'delete', 'superuser'],
  },
  editor: { role: 'editor', capabilities: ['create', 'read', 'update'] },
  user: { role: 'user', capabilities: ['read'] },
};

beforeAll(async done => {
  let rolesDB = new Roles();
  await supertester.startDB();
  await rolesDB.create(roles.admin);
  await rolesDB.create(roles.editor);
  await rolesDB.create(roles.user);
  done();
});

afterAll(supertester.stopDB);

describe('routes testing', () => {
  it('Unathenticated users can only access public', () => { });
}); 