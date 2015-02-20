# net-chrome-apps
Use the net module of node in [Chrome Apps](https://developer.chrome.com/apps)!
This module is a wrapper around the [Chrome Apps TCP Sockets API](https://developer.chrome.com/apps/sockets_tcp).
It was built by taking the lib/net.js file of Node code v0.12.0 and modifying it
to use the Chrome API.

## install / usage with browserify

```bash
npm install net-chrome-apps
```

To use it with browserify, you have to use the js API of browserify;
the command line API does not support changing builtins.

Example:

```js
var browserify = require('browserify');

var builtins = require('browserify/lib/builtins.js');
builtins.net = require.resolve('net-chrome-apps');

var b = browserify();

b.add(...
```

The above example will use net-chrome-apps for all browserify builds.
If you only want it for a specific build of a larger build script:

```js
var browserify = require('browserify');

var builtins = require('browserify/lib/builtins.js');
var myBuiltins = {};
Object.keys(builtins).forEach(function(key) {
  myBuiltins[key] = builtins[key];
});

myBuiltins.net = require.resolve('net-chrome-apps')

var b = browserify({builtins: myBuiltins});

b.add(...
```

You probably also want to use the http module of Node. You can use
[http-node](https://www.npmjs.com/package/http-node) for that. Combined snippet:

```js
var browserify = require('browserify');

var builtins = require('browserify/lib/builtins.js');
builtins.net = require.resolve('net-chrome-apps');
builtins.http = require.resolve('http-node');

var b = browserify();

b.add(...
```

## similar projects & status

There are already other projects that do the same thing. However, I found that
they were just "proofs of concept", and not really maintained anymore. Also they
still use the old chrome.socket API. Until now, 2015-2-20, I found:

- [GoogleChrome/net-chromeify](https://github.com/GoogleChrome/net-chromeify) and forked from/based on that [iceddev/node-chromify](https://github.com/iceddev/node-chromify) - latest commit 26 Nov 2013
- [tilgovi/chromify](https://github.com/tilgovi/chromify) - shims process.binding - latest commit 26 Jan 2013

This is intended to be a robust, efficient and compatible implementation. For example, it
pauses the socket if the incoming buffer is full, unlike the others. However,
what is currently missing are tests. Also, it'd be possible to make something
similar with the UDP API.

## credit

The code is originally based on the [Node.js](http://nodejs.org) project:
Copyright Joyent, Inc. and other Node contributors.

Node.js is a registered trademark of Joyent, Inc. in the United states and other countries. This
package is not formally related to or endorsed by the official Joyent Node.js project.

## license

MIT
