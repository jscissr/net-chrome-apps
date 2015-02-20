// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// Modified to use Chrome Apps API by Jan Schär, 2015
// based on lib/net.js of node v0.12.0

var events = require('events');
var stream = require('stream');
var timers = require('timers');
var util = require('util');
var assert = require('assert');

var Buffer = require('buffer').Buffer;

function errnoException(err, syscall) {
  var message = syscall + ' ' + err;
  if (chrome.runtime.lastError) {
    message +=  ' ' + chrome.runtime.lastError.message;
  }
  var e = new Error(message);
  e.code = err;
  e.errno = err;
  e.syscall = syscall;
  return e;
}

function noop() {}


function cbChrome(func) {
  return function() {
    try {
      return func.apply(this, arguments);
    } catch (e) {
      console.error(e); // Errors are logged on the background page otherwise
    }
  };
}


var idToServerInstance = {},
    idToSocketInstance = {};

var socketIdPool = [],
    serverIdPool = [];

/**
 * The underlying sockets (identified by socketId) can be reused after
 * disconnecting. This limits the size of the pool. For tcp.Server, this pool
 * is not used for new connections, but once disconnected they are also put into
 * the pool. If you don't need client sockets, you can set this to 0.
 * @type {number}
 */
exports.socketPoolSize = 5;
/**
 * The underlying server sockets (identified by socketId) can be reused after
 * disconnecting. This limits the size of the pool.
 * @type {number}
 */
exports.serverPoolSize = 1;

function createSocket(cb) {
  var socketId = socketIdPool.pop();
  if (socketId) {
    // reset properties
    var properties = {
      persistent: false,
      name: '',
      bufferSize: 0
    };

    // keepAlive and noDelay are reset by the underlying API when calling connect
    chrome.sockets.tcp.setPaused(socketId, true);
    chrome.sockets.tcp.update(socketId, properties, cbChrome(function() {
      cb(socketId);
    }));
  } else {
    chrome.sockets.tcp.create(cbChrome(function(createInfo) {
      chrome.sockets.tcp.setPaused(createInfo.socketId, true);
      cb(createInfo.socketId);
    }));
  }
}

function closeSocket(socketId) {
  delete idToSocketInstance[socketId];
  if (socketIdPool.length >= exports.socketPoolSize) {
    chrome.sockets.tcp.close(socketId);
  } else {
    chrome.sockets.tcp.disconnect(socketId, cbChrome(function() {
      socketIdPool.push(socketId);
    }));
  }
}

function createServer(cb) {
  var socketId = serverIdPool.pop();
  if (socketId) {
    var properties = {
      persistent: false,
      name: ''
    };
    chrome.sockets.tcpServer.setPaused(socketId, false);
    chrome.sockets.tcpServer.update(socketId, properties, cbChrome(function() {
      cb(socketId);
    }));
  } else {
    chrome.sockets.tcpServer.create(cbChrome(function(createInfo) {
      cb(createInfo.socketId);
    }));
  }
}

function closeServer(socketId) {
  delete idToServerInstance[socketId];
  if (serverIdPool.length >= exports.serverPoolSize) {
    chrome.sockets.tcpServer.close(socketId);
  } else {
    chrome.sockets.tcpServer.disconnect(socketId, cbChrome(function() {
      serverIdPool.push(socketId);
    }));
  }
}


function onAccept(info) {
  var self = idToServerInstance[info.socketId];
  if (!self) {
    return;
  }
  if (self.maxConnections && self._connections >= self.maxConnections) {
    closeSocket(info.clientSocketId);
    return;
  }
  debug(info.socketId +
      ': onAccept; socketId: ' + info.clientSocketId);

  var socket = new Socket({
    _socketId: info.clientSocketId,
    allowHalfOpen: self.allowHalfOpen,
    pauseOnCreate: self.pauseOnConnect
  });
  socket.readable = socket.writable = true;

  self._connections++;
  socket.server = self;

  // DTRACE_NET_SERVER_CONNECTION(socket);
  // COUNTER_NET_SERVER_CONNECTION(socket);
  self.emit('connection', socket);
}

function onAcceptError(info) {
  var self = idToServerInstance[info.socketId];
  if (!self) {
    return;
  }
  debug(info.socketId + ': onAcceptError ' + info.resultCode);

  self.emit('error', errnoException(info.resultCode, 'accept'));
  self.close();
}

function onReceive(info) {
  var self = idToSocketInstance[info.socketId];
  if (!self) {
    return;
  }

  timers._unrefActive(self);

  debug('onread', info.data.byteLength);
  self.bytesRead += info.data.byteLength;

  // assuming https://github.com/feross/buffer implementation
  var ret = self.push(Buffer._augment(new Uint8Array(info.data)));

  if (!self._isPaused && !ret) {
    debug('readStop');
    self._isPaused = true;
    chrome.sockets.tcp.setPaused(self._socketId, true);
  }
}

function onReceiveError(info) {
  var self = idToSocketInstance[info.socketId];
  if (!self) {
    return;
  }

  if (info.resultCode === -100) { // net::ERR_CONNECTION_CLOSED
    debug('EOF');

    if (self._readableState.length === 0) {
      self.readable = false;
      maybeDestroy(self);
    }

    // push a null to signal the end of data.
    self.push(null);

    // internal end event so that we know that the actual socket
    // is no longer readable, and we can start the shutdown
    // procedure. No need to wait for all the data to be consumed.
    self.emit('_socketEnd');
  } else {
    // in events, chrome.runtime.lastError is not set
    self._destroy(errnoException(info.resultCode, 'read'));
  }
}

chrome.sockets.tcpServer.onAccept.addListener(cbChrome(onAccept));
chrome.sockets.tcpServer.onAcceptError.addListener(cbChrome(onAcceptError));
chrome.sockets.tcp.onReceive.addListener(cbChrome(onReceive));
chrome.sockets.tcp.onReceiveError.addListener(cbChrome(onReceiveError));


var debug = console.log.bind(console); // util.debuglog('net');

function isPipeName(s) {
  return util.isString(s) && toNumber(s) === false;
}


exports.createServer = function(options, connectionListener) {
  return new Server(options, connectionListener);
};


// Target API:
//
// var s = net.connect({port: 80, host: 'google.com'}, function() {
//   ...
// });
//
// There are various forms:
//
// connect(options, [cb])
// connect(port, [host], [cb])
// connect(path, [cb]);
//
exports.connect = exports.createConnection = function() {
  var args = normalizeConnectArgs(arguments);
  debug('createConnection', args);
  var s = new Socket(args[0]);
  return Socket.prototype.connect.apply(s, args);
};

// Returns an array [options] or [options, cb]
// It is the same as the argument of Socket.prototype.connect().
function normalizeConnectArgs(args) {
  var options = {};

  if (util.isObject(args[0])) {
    // connect(options, [cb])
    options = args[0];
  } else if (isPipeName(args[0])) {
    // connect(path, [cb]);
    throw new Error('Pipes are not supported in Chrome Apps.');
  } else {
    // connect(port, [host], [cb])
    options.port = args[0];
    if (util.isString(args[1])) {
      options.host = args[1];
    }
  }

  var cb = args[args.length - 1];
  return util.isFunction(cb) ? [options, cb] : [options];
}
exports._normalizeConnectArgs = normalizeConnectArgs;


// called when creating new Socket, or when re-using a closed Socket
function initSocket(self) {
  self.bytesRead = 0;
  self._bytesDispatched = 0;
}

function Socket(options) {
  if (!(this instanceof Socket)) return new Socket(options);

  this._connecting = false;
  this.destroyed = false;
  this._hadError = false;
  this._socketId = null; // a number > 0
  this._host = null;
  this._port = null;

  this._peername = {};
  this._sockname = {};
  this._isPaused = true;

  if (util.isNumber(options))
    options = { fd: options }; // Legacy interface.
  else if (util.isUndefined(options))
    options = {};

  options.decodeStrings = true;
  options.objectMode = false;
  stream.Duplex.call(this, options);

  if (options._socketId) {
    this._socketId = options._socketId;
    idToSocketInstance[this._socketId] = this;
  } else if (options.handle) {
    throw new Error('handle is not supported in Chrome Apps.');
  } else if (!util.isUndefined(options.fd)) {
    throw new Error('fd is not supported in Chrome Apps.');
  } else {
    // these will be set once there is a connection
    this.readable = this.writable = false;
  }

  // shut down the socket when we're finished with it.
  this.on('finish', onSocketFinish);
  this.on('_socketEnd', onSocketEnd);

  initSocket(this);

  this._pendingData = null;

  // default to *not* allowing half open sockets
  this.allowHalfOpen = options && options.allowHalfOpen || false;

  // if we have a socketId, then start the flow of data into the
  // buffer.  if not, then this will happen when we connect
  if (this._socketId && options.readable !== false) {
    if (options.pauseOnCreate) {
      // stop the handle from reading and pause the stream
      // (Already paused in Chrome version)
      this._readableState.flowing = false;
    } else {
      this.read(0);
    }
  }
}
util.inherits(Socket, stream.Duplex);

// the user has called .end(), and all the bytes have been
// sent out to the other side.
// If allowHalfOpen is false, or if the readable side has
// ended already, then destroy.
// If allowHalfOpen is true, then we need to do a shutdown,
// so that only the writable side will be cleaned up.
function onSocketFinish() {
  if (this.destroyed)
      return;

  // If still connecting - defer handling 'finish' until 'connect' will happen
  if (this._connecting) {
    debug('osF: not yet connected');
    return this.once('connect', onSocketFinish);
  }

  debug('onSocketFinish');
  if (!this.readable || this._readableState.ended) {
    debug('oSF: ended, destroy', this._readableState);
    return this.destroy();
  }

  debug('oSF: not ended, call shutdown()');

  // otherwise, just shutdown
  // the chrome.sockets.tcp implementation does not support half-open sockets,
  // see https://code.google.com/p/chromium/issues/detail?id=124952

  this.destroy();
}

// the EOF has been received, and no more bytes are coming.
// if the writable side has ended already, then clean everything
// up.
function onSocketEnd() {
  // XXX Should not have to do as much crap in this function.
  // ended should already be true, since this is called *after*
  // the EOF errno and onread has eof'ed
  debug('onSocketEnd', this._readableState);
  this._readableState.ended = true;
  if (this._readableState.endEmitted) {
    this.readable = false;
    maybeDestroy(this);
  } else {
    this.once('end', function() {
      this.readable = false;
      maybeDestroy(this);
    });
    this.read(0);
  }

  if (!this.allowHalfOpen) {
    this.write = writeAfterFIN;
    this.destroySoon();
  }
}

// Provide a better error message when we call end() as a result
// of the other side sending a FIN.  The standard 'write after end'
// is overly vague, and makes it seem like the user's code is to blame.
function writeAfterFIN(chunk, encoding, cb) {
  if (util.isFunction(encoding)) {
    cb = encoding;
    encoding = null;
  }

  var er = new Error('This socket has been ended by the other party');
  er.code = 'EPIPE';
  var self = this;
  // TODO: defer error events consistently everywhere, not just the cb
  self.emit('error', er);
  if (util.isFunction(cb)) {
    process.nextTick(function() {
      cb(er);
    });
  }
}

exports.Socket = Socket;
exports.Stream = Socket; // Legacy naming.

Socket.prototype.read = function(n) {
  if (n === 0)
    return stream.Readable.prototype.read.call(this, n);

  this.read = stream.Readable.prototype.read;
  this._consuming = true;
  return this.read(n);
};


Socket.prototype.listen = function() {
  debug('socket.listen');
  var self = this;
  self.on('connection', arguments[0]);
  self._listen2(null, null);
};


Socket.prototype.setTimeout = function(msecs, callback) {
  if (msecs === 0) {
    timers.unenroll(this);
    if (callback) {
      this.removeListener('timeout', callback);
    }
  } else {
    timers.enroll(this, msecs);
    timers._unrefActive(this);
    if (callback) {
      this.once('timeout', callback);
    }
  }
};


Socket.prototype._onTimeout = function() {
  debug('_onTimeout');
  this.emit('timeout');
};


Socket.prototype.setNoDelay = function(enable) {
  if (this._socketId) {
    // backwards compatibility: assume true when `enable` is omitted
    chrome.sockets.tcp.setNoDelay(this._socketId,
        util.isUndefined(enable) ? true : !!enable,
        cbChrome(function(result) {
          if (result !== 0) {
            debug('Error: setNoDelay failed');
            // TODO: error
          }
        }));
  }
};


Socket.prototype.setKeepAlive = function(setting, msecs) {
  if (this._socketId) {
    chrome.sockets.tcp.setKeepAlive(this._socketId, !!setting, ~~(msecs / 1000),
        cbChrome(function(result) {
          if (result !== 0) {
            debug('Error: setKeepAlive failed');
            // TODO: error
          }
        }));
  }
};


Socket.prototype.address = function() {
  return this._getsockname();
};


Object.defineProperty(Socket.prototype, 'readyState', {
  get: function() {
    if (this._connecting) {
      return 'opening';
    } else if (this.readable && this.writable) {
      return 'open';
    } else if (this.readable && !this.writable) {
      return 'readOnly';
    } else if (!this.readable && this.writable) {
      return 'writeOnly';
    } else {
      return 'closed';
    }
  }
});


Object.defineProperty(Socket.prototype, 'bufferSize', {
  get: function() {
    if (this._socketId) {
      return this._writableState.length;
    }
  }
});


// Just call readStart until we have enough in the buffer
Socket.prototype._read = function(n) {
  debug('_read');

  if (this._connecting || !this._socketId) {
    debug('_read wait for connection');
    this.once('connect', this._read.bind(this, n));
  } else if (this._isPaused) {
    // not already reading, start the flow
    debug('Socket._read readStart');
    this._isPaused = false;
    chrome.sockets.tcp.setPaused(this._socketId, false);
  }
};


Socket.prototype.end = function(data, encoding) {
  stream.Duplex.prototype.end.call(this, data, encoding);
  this.writable = false;
  // DTRACE_NET_STREAM_END(this);

  // just in case we're waiting for an EOF.
  if (this.readable && !this._readableState.endEmitted)
    this.read(0);
  else
    maybeDestroy(this);
};


// Call whenever we set writable=false or readable=false
function maybeDestroy(socket) {
  if (!socket.readable &&
      !socket.writable &&
      !socket.destroyed &&
      !socket._connecting &&
      !socket._writableState.length) {
    socket.destroy();
  }
}


Socket.prototype.destroySoon = function() {
  if (this.writable)
    this.end();

  if (this._writableState.finished)
    this.destroy();
  else
    this.once('finish', this.destroy);
};


Socket.prototype._destroy = function(exception, cb) {
  debug('destroy');

  var self = this;

  function fireErrorCallbacks() {
    if (cb) cb(exception);
    if (exception && !self._writableState.errorEmitted) {
      process.nextTick(function() {
        self.emit('error', exception);
      });
      self._writableState.errorEmitted = true;
    }
  };

  if (this.destroyed) {
    debug('already destroyed, fire error callbacks');
    fireErrorCallbacks();
    return;
  }

  self._connecting = false;

  this.readable = this.writable = false;

  self._peername = {};
  self._sockname = {};

  timers.unenroll(this);

  debug('close');
  if (this._socketId) {
    debug('close handle');
    var isException = exception ? true : false;
    process.nextTick(function() {
      debug('emit close');
      self.emit('close', isException);
    });
    closeSocket(self._socketId);
    self._socketId = null;
  }

  // we set destroyed to true before firing error callbacks in order
  // to make it re-entrance safe in case Socket.prototype.destroy()
  // is called within callbacks
  this.destroyed = true;
  fireErrorCallbacks();

  if (this.server) {
    // COUNTER_NET_SERVER_CONNECTION_CLOSE(self);
    debug('has server');
    this.server._connections--;
    if (this.server._emitCloseIfDrained) {
      this.server._emitCloseIfDrained();
    }
  }
};


Socket.prototype.destroy = function(exception) {
  debug('destroy', exception);
  this._destroy(exception);
};


Socket.prototype._getpeername = function() {
  return this._peername;
};


Socket.prototype.__defineGetter__('remoteAddress', function() {
  return this._getpeername().address;
});

Socket.prototype.__defineGetter__('remoteFamily', function() {
  return this._getpeername().family;
});

Socket.prototype.__defineGetter__('remotePort', function() {
  return this._getpeername().port;
});


Socket.prototype._getsockname = function() {
  return this._sockname;
};


Socket.prototype.__defineGetter__('localAddress', function() {
  return this._getsockname().address;
});


Socket.prototype.__defineGetter__('localPort', function() {
  return this._getsockname().port;
});


Socket.prototype._write = function(chunk, encoding, cb) {
  if (!ArrayBuffer.isView(chunk))
    throw new TypeError('invalid data (must be an Uint8Array)');
  var self = this;
  // If we are still connecting, then buffer this for later.
  // The Writable logic will buffer up any more writes while
  // waiting for this one to be done.
  if (this._connecting) {
    this._pendingData = chunk;
    this.once('connect', function() {
      self._pendingData = null;
      self._write(chunk, encoding, cb);
    });
    return;
  }

  timers._unrefActive(this);

  if (!this._socketId) {
    this._destroy(new Error('This socket is closed.'), cb);
    return false;
  }

  var arrayBuffer;
  if (chunk.byteOffset === 0 &&
      chunk.byteLength === chunk.buffer.byteLength) {
    arrayBuffer = chunk.buffer;
  } else {
    arrayBuffer = chunk.buffer.slice(chunk.byteOffset,
        chunk.byteOffset + chunk.byteLength);
  }
  chrome.sockets.tcp.send(this._socketId, arrayBuffer, cbChrome(function(sendInfo){
    // callback may come after call to destroy.
    if (self.destroyed) {
      debug('afterWrite destroyed');
      return;
    }
    if (sendInfo.resultCode !== 0) {
      self.destroy(errnoException(sendInfo.resultCode, 'write'), cb);
    } else {
      timers._unrefActive(self);
      // The Chrome API buffers 32 KiB before stopping to call the callback
      // until a TCP ACK is received.
      cb();
    }
  }));

  this._bytesDispatched += arrayBuffer.byteLength;
};


Socket.prototype.__defineGetter__('bytesWritten', function() {
  var bytes = this._bytesDispatched + this._writableState.length,
      data = this._pendingData;
  if (data) {
    bytes += data.length;
  }
  return bytes;
});


Socket.prototype.connect = function(options, cb) {
  if (this.write !== Socket.prototype.write)
    this.write = Socket.prototype.write;

  if (!util.isObject(options)) {
    // Old API:
    // connect(port, [host], [cb])
    // connect(path, [cb]);
    var args = normalizeConnectArgs(arguments);
    return Socket.prototype.connect.apply(this, args);
  }

  if (this._socketId) {
    debug('connect: already connected, destroy and connect again');
    this.destroy();
  }

  if (this.destroyed) {
    this._readableState.reading = false;
    this._readableState.ended = false;
    this._readableState.endEmitted = false;
    this._writableState.ended = false;
    this._writableState.ending = false;
    this._writableState.finished = false;
    this._writableState.errorEmitted = false;
    this._writableState.length = 0;
    this.destroyed = false;
  }

  var self = this;
  if (options.path) {
    throw new Error('Pipes are not supported in Chrome Apps.');
  }

  if (util.isFunction(cb)) {
    self.once('connect', cb);
  }

  timers._unrefActive(this);

  self._connecting = true;
  self.writable = true;

  this._host = options.host || 'localhost';
  this._port = options.port | 0;

  if (this._port <= 0 || this._port > 65535)
    throw new RangeError('Port should be > 0 and < 65536: ' + this._port);


  createSocket(function(socketId) {
    if (!self._connecting || self._socketId) {
      closeSocket(socketId);
      return;
    }
    self._socketId = socketId;
    idToSocketInstance[socketId] = self;
    chrome.sockets.tcp.connect(socketId, self._host, self._port,
        cbChrome(function(result) {
          afterConnect(self, result, socketId);
        }));
  });
  initSocket(this);
  return this;
};

// This mechanism doesn't work in Chrome Apps
Socket.prototype.ref = Socket.prototype.unref = noop;


function afterConnect(self, result, socketId) {
  // callback may come after call to destroy
  if (self._socketId !== socketId) {
    closeSocket(socketId);
    return;
  }

  debug('afterConnect');

  if (result === 0) {
    chrome.sockets.tcp.getInfo(socketId, cbChrome(function(info) {
      // callback may come after call to destroy
      if (self._socketId !== socketId) {
        closeSocket(socketId);
        return;
      }
      assert.ok(self._connecting);
      self._connecting = false;

      self._sockname = {
        port: info.localPort,
        family: info.localAddress && info.localAddress.indexOf(':') !== -1 ?
          'IPv6' : 'IPv4',
        address: info.localAddress
      };
      self._peername = {
        port: info.peerPort,
        family: info.peerAddress && info.peerAddress.indexOf(':') !== -1 ?
          'IPv6' : 'IPv4',
        address: info.peerAddress
      };

      self.readable = true;
      self.writable = true;
      timers._unrefActive(self);

      self.emit('connect');

      // start the first read, or get an immediate EOF.
      // this doesn't actually consume any bytes, because len=0.
      if (!(self.isPaused && self.isPaused()))
        self.read(0);
    }));
  } else {
    self._destroy(errnoException(result, 'connect'));
  }
}


function Server(options, connectionListener) {
  if (!(this instanceof Server))
    return new Server(options, connectionListener);

  events.EventEmitter.call(this);

  var self = this;

  if (util.isFunction(options)) {
    connectionListener = options;
    options = {};
    this.on('connection', connectionListener);
  } else {
    options = options || {};

    if (util.isFunction(connectionListener))
      this.on('connection', connectionListener);
  }

  this._connections = 0;

  Object.defineProperty(this, 'connections', {
    get: util.deprecate(function() {
      return self._connections;
    }, 'connections property is deprecated. Use getConnections() method'),
    set: util.deprecate(function(val) {
      return (self._connections = val);
    }, 'connections property is deprecated. Use getConnections() method'),
    configurable: true, enumerable: false
  });

  this._socketId = null; // a number > 0
  this._connecting = false;

  this.allowHalfOpen = options.allowHalfOpen || false;
  this.pauseOnConnect = !!options.pauseOnConnect;
  this._address = null;

  this._host = null;
  this._port = null;
  this._backlog = null;
}
util.inherits(Server, events.EventEmitter);
exports.Server = Server;

Server.prototype._usingSlaves = false; // not used


function toNumber(x) { return (x = Number(x)) >= 0 ? x : false; }


// exports._createServerHandle not supported

function afterListen(self, result, socketId) {
  debug('afterListen');

  assert.ok(self._connecting);
  self._connecting = false;

  if (result === 0) {
    chrome.sockets.tcpServer.getInfo(socketId, cbChrome(function(info) {
      self._address = {
        port: info.localPort,
        family: info.localAddress && info.localAddress.indexOf(':') !== -1 ?
          'IPv6' : 'IPv4',
        address: info.localAddress
      };

      self.emit('listening');
    }));
  } else {
    var ex = errnoException(result, 'listen');
    self.emit('error', ex);
    closeServer(socketId);
    this._socketId = null;
  }
}

Server.prototype._listen2 = function(address, port, backlog) {
  debug('listen2', address, port, backlog);
  var self = this;

  if (self._socketId) {
    debug('_listen2: already listening, close and listen again');
    self.close();
  }

  self._port = port | 0;
  if (self._port < 0 || self._port > 65535) // allow 0 for random port
    throw new RangeError('Port should be >= 0 and < 65536');

  self._host = address;

  var isAny = !self._host;
  if (isAny)
    self._host = '::';

  self._backlog = (backlog || backlog === 0) ? backlog : undefined;

  self._connecting = true;

  debug('_listen2: create a socketId');
  createServer(function(socketId) {
    if (!self._connecting || self._socketId) {
      closeServer(socketId);
      return;
    }
    self._socketId = socketId;
    idToServerInstance[socketId] = self;
    debug('listen on ' +
        (self._host.indexOf(':') !== -1 ? '[' + self._host + ']' : self._host) +
        ':' + self._port);

    function listen(){
      chrome.sockets.tcpServer.listen(socketId, self._host, self._port,
          self._backlog, cbChrome(function(result) {
            // callback may come after call to close
            if (self._socketId !== socketId) {
              closeServer(socketId);
              return;
            }
            if (result !== 0 && isAny) {
              self._host = '0.0.0.0'; // try IPv4
              isAny = false;
              return listen();
            }
            afterListen(self, result, socketId);
          }));
    }
    listen();
  });

  // generate connection key, this should be unique to the connection
  self._connectionKey = self._host + ':' + self._port;
};

Server.prototype.listen = function() {
  var self = this;

  var lastArg = arguments[arguments.length - 1];
  if (util.isFunction(lastArg)) {
    self.once('listening', lastArg);
  }

  var port = toNumber(arguments[0]);

  // The third optional argument is the backlog size.
  // When the ip is omitted it can be the second argument.
  var backlog = toNumber(arguments[1]) || toNumber(arguments[2]);

  if (util.isObject(arguments[0])) {
    var h = arguments[0];

    if (h._handle || h.handle) {
      throw new Error('handle is not supported in Chrome Apps.');
    }
    if (util.isNumber(h.fd) && h.fd >= 0) {
      throw new Error('fd is not supported in Chrome Apps.');
    }

    // The first argument is a configuration object
    if (h.backlog)
      backlog = h.backlog;

    if (util.isNumber(h.port)) {
      if (h.host)
        self._listen2(h.host, h.port, backlog);
      else
        self._listen2(null, h.port, backlog);
    } else if (h.path && isPipeName(h.path)) {
      throw new Error('Pipes are not supported in Chrome Apps.');
    } else {
      throw new Error('Invalid listen argument: ' + h);
    }
  } else if (isPipeName(arguments[0])) {
    // UNIX socket or Windows pipe.
    throw new Error('Pipes are not supported in Chrome Apps.');
  } else if (util.isUndefined(arguments[1]) ||
             util.isFunction(arguments[1]) ||
             util.isNumber(arguments[1])) {
    // The first argument is the port, no IP given.
    self._listen2(null, port, backlog);
  } else {
    // The first argument is the port, the second an IP.
    self._listen2(arguments[1], port, backlog);
  }

  return self;
};

Server.prototype.address = function() {
  return this._address;
};


Server.prototype.getConnections = function(cb) {
  process.nextTick(function() {
    cb(null, this._connections);
  });
};


Server.prototype.close = function(cb) {
  if (cb) {
    if (!this._socketId) {
      this.once('close', function() {
        cb(new Error('Not running'));
      });
    } else {
      this.once('close', cb);
    }
  }

  if (this._socketId) {
    closeServer(this._socketId);
    this._socketId = null;
  }
  this._address = null;
  this._connecting = false;

  this._emitCloseIfDrained();

  return this;
};

Server.prototype._emitCloseIfDrained = function() {
  debug('SERVER _emitCloseIfDrained');
  var self = this;

  if (self._socketId || self._connections) {
    debug('SERVER socketId? %s   connections? %d',
          !!self._socketId, self._connections);
    return;
  }

  process.nextTick(function() {
    debug('SERVER: emit close');
    self.emit('close');
  });
};


Server.prototype.listenFD = util.deprecate(function(fd, type) {
  return this.listen({ fd: fd });
}, 'listenFD is deprecated. Use listen({fd: <number>}).');

Server.prototype._setupSlave = function(socketList) {
  throw new Error('Slaves are not supported in Chrome Apps.');
};

// This mechanism doesn't work in Chrome Apps
Server.prototype.ref = Server.prototype.unref = noop;


// TODO: isIP should be moved to the DNS code. Putting it here now because
// this is what the legacy system did.

var IPv4regex = /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/,
    // Either percent sign or end of string at end
    IPv6regex = /^[0-9a-f:]+(?::[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)?(?:%|$)/i;
exports.isIP = function(input) {
  if (util.isString(input)) {
    if (IPv4regex.test(input)) {
      var parts = input.split('.');
      for (var i = 0; i < 4; i++) {
        if ((parts[i].length > 1 && parts[i].charAt(0) === '0') ||
            parts[i] > 255) {
          return 0;
        }
      }
      return 4;
    } else if (IPv6regex.test(input)) {
      if (input.indexOf('%') > -1) {
        input = input.substr(0, input.indexOf('%')); // Remove ipv6 scope
      }

      var groups = 8,
        parts = input.split(':'),
        seenTwoColon = false;
      if (parts[parts.length - 1].indexOf('.') > -1) { // Integrated IPv4 syntax
        if (!exports.isIPv4(parts.pop())) {
          return 0;
        }
        groups = 6;
      } else if (parts[parts.length - 1] === '') { // :: at the end
        if (parts[parts.length - 2] !== '') {
          return 0;
        }
        parts.pop();
      }
      if (parts[0] === '') { // :: at the start
        if (parts[1] !== '') { // This also catches the input ':'
          return 0;
        }
        parts.shift();
      }
      if (parts.length > groups) {
        return 0;
      }
      for (var i = 0; i < parts.length; i++) {
        if (parts[i].length > 4) {
          return 0;
        } else if (parts[i] === '') {
          if (seenTwoColon) {
            return 0;
          }
          seenTwoColon = true;
        }
      }
      if (!seenTwoColon && parts.length !== groups) {
        return 0;
      }
      return 6;
    }
  }
  return 0;
};

exports.isIPv4 = function(input) {
  return exports.isIP(input) === 4;
};


exports.isIPv6 = function(input) {
  return exports.isIP(input) === 6;
};


exports._setSimultaneousAccepts = noop;
