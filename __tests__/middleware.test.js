'use strict';

const { startDB, stopDB } = require('./supertester.js');
const auth = require('../src/auth/middleware.js');
const Users = require('../src/auth/users-model.js');
const Roles = require('../src/auth/roles-model.js');

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
  await startDB();
  const admin = await new Users(users.admin).save();
  const editor = await new Users(users.editor).save();
  const user = await new Users(users.user).save();
  const adminRole = await new Roles(roles.admin).save();
  const editorRole = await new Roles(roles.editor).save();
  const userRole = await new Roles(roles.user).save();
  done();
});

afterAll(stopDB);

/* describe('xxx', () => {
  it('xxx', () => { }); 
}); */
