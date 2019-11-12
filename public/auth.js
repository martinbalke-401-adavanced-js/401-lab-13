'use strict';

let token = '';

/**
 * This function shows show simple it can be to encode something using base64 encoding. Note, this is client-side javascript, and so we don't have access to the Buffer class. So, we use a built-in function that does base64 encoding, btoa
 * @param  {string} username  The username to encode
 * @param  {string} password  The plain-text password to encode
 * @return {string}           A base 64 encoded string of the format 'Basic username:password'
 */
const encode = (username, password) => {
  let encoded = btoa(username + ':' + password);
  return 'Basic ' + encoded;
};

/**
 * This function captures user input from the form, encodes the username and password, and then sends a request to our server, asking our server to authenticate the user and return us a token
 * @param  {object} e  This is the event object that is returned from the form HTML element. We need this so that we can prevent the form from causing a page refresh and so that we can grab the form inputs
 */
const basicAuth = async e => {
  e.preventDefault();

  // Grab form inputs
  let username = e.target[0].value;
  let password = e.target[1].value;
  let timeout = e.target[2].checked;

  // Error message if not the correct input
  if (!username || !password)
    sendMessage('Please enter in a username and password');
  else {
    // Encode username and password
    let bAuthData = encode(username, password);
    sendMessage(`Converted data to encoded:\n${bAuthData}`);

    // POST to /signin route - I want to verify this user
    // and receive a JSON Web Token
    let authResponse = await fetch('/signin', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: bAuthData,
        Timeout: timeout,
      },
    });

    // Grab the response body as JSON
    let authData = await authResponse.json();

    let message =
      'Received response' +
      '\n' +
      authResponse.status +
      ' ' +
      authResponse.statusText;
    sendMessage(message);

    // If we got a successful response, we should have a token
    if (authResponse.status === 200) {
      sendMessage(
        `Successfully logged in and recieved token:\n${authData.token}`,
      );

      token = authData.token;
    }
  }
};

/**
 * This function attempts to validate that we can access the /public route
 */
const getPublic = async () => {
  let res = await fetch('/role/public', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
  });

  let data = await res.json();

  if (data.valid) sendMessage('You are now viewing a public message!', 'green');
};

/**
 * This function attempts to validate that we can access the /hidden route
 */
const getHidden = async () => {
  let res = await fetch('/role/hidden', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: token,
    },
  });

  let data = await res.json();

  if (data.valid)
    sendMessage(
      'You are now viewing a hidden message! Only logged in users get to see this',
      'green',
    );
  else sendMessage(`Uh oh! Looks like we got an error: ${data.error}`, 'red');
};

/**
 * This function attempts to validate that we can access the /read-only route
 */
const getReadOnly = async () => {
  let res = await fetch('/role/read-only', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: token,
    },
  });

  let data = await res.json();

  if (data.valid)
    sendMessage(
      'You are now viewing a message that only users with the READ capability can see. Lucky you!',
      'green',
    );
  else sendMessage(`Uh oh! Looks like we got an error: ${data.error}`, 'red');
};

/**
 * This function attempts to validate that we can access the post /create route
 */
const postCreate = async () => {
  let res = await fetch('/role/create', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: token,
    },
  });

  let data = await res.json();

  if (data.valid)
    sendMessage(
      'Success! You have the power to create new entries. Use it wisely!',
      'green',
    );
  else sendMessage(`Uh oh! Looks like we got an error: ${data.error}`, 'red');
};

/**
 * This function attempts to validate that we can access the put /update/:id route
 */
const putUpdate = async () => {
  let res = await fetch('/role/update/1', {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: token,
    },
  });

  let data = await res.json();

  if (data.valid)
    sendMessage('You are able to update items! What a great ability!', 'green');
  else sendMessage(`Uh oh! Looks like we got an error: ${data.error}`, 'red');
};

/**
 * This function attempts to validate that we can access the delete /delete/:id route
 */
const delDelete = async () => {
  let res = await fetch('/role/delete/1', {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: token,
    },
  });

  let data = await res.json();

  if (data.valid)
    sendMessage('You are able to delete items, so be careful!', 'green');
  else sendMessage(`Uh oh! Looks like we got an error: ${data.error}`, 'red');
};

/**
 * This function attempts to validate that we can access the /super route
 */
const getSuper = async () => {
  let res = await fetch('/role/super', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: token,
    },
  });

  let data = await res.json();

  if (data.valid) sendMessage('VIP access for a super user like you!', 'green');
  else sendMessage(`Uh oh! Looks like we got an error: ${data.error}`, 'red');
};

/**
 * This function is just a client bootstrap-oriented function which generates popup messages that fade away after a short period of time
 * @param  {string} message   The message to print in the popup
 */
const sendMessage = (message, className) => {
  let toastId = 'toast-' + Date.now();
  let toast = '<div class="toast ';

  toast += className + '" ';

  toast += 'id="' + toastId + '"';
  toast +=
    ' role="alert" aria-live="assertive" aria-atomic="true"><div class="toast-header"><h4 class="mr-auto">';

  toast += 'Message';

  toast += '</h4><p>';

  let date = new Date();
  toast += date.toLocaleString();

  toast +=
    '</p><button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close"><span aria-hidden="true">&times;</span></button></div><p class="lead toast-body">';

  toast += message;

  toast += '</p></div>';

  $('#bAuth-message').append(toast);
  $('#' + toastId).toast({
    delay: 5000,
  });

  $('#' + toastId).toast('show');
};
