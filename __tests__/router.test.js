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
  await supertester.startDB();
  const admin = await new Roles(roles.admin).save();
  const editor = await new Roles(roles.editor).save();
  const user = await new Roles(roles.user).save();
  done();
});

afterAll(supertester.stopDB);

/* describe('xxx', () => {
  it('xxx', () => { }); 
}); */
