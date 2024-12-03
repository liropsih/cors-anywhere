'use strict';

const cors_proxy = require('./lib/cors-anywhere');
const originBlacklist = parseEnvList(process.env.CORSANYWHERE_BLACKLIST);
const originWhitelist = parseEnvList(process.env.CORSANYWHERE_WHITELIST);
const checkRateLimit = require('./lib/rate-limit')(process.env.CORSANYWHERE_RATELIMIT);

function parseEnvList(env) {
  if (!env) {
    return [];
  }
  return env.split(',');
}

const server = cors_proxy.createServer({
  originBlacklist: originBlacklist,
  originWhitelist: originWhitelist,
  requireHeader: ['origin', 'x-requested-with'],
  checkRateLimit: checkRateLimit,
  removeHeaders: [
    'cookie',
    'cookie2',
    'x-request-start',
    'x-request-id',
    'via',
    'connect-time',
    'total-route-time',
  ],
  redirectSameOrigin: true,
  httpProxyOptions: {
    xfwd: false,
  },
});

function addCorsHeaders(headers) {
  headers['Access-Control-Allow-Origin'] = '*';
  headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
  headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept';
}

module.exports.proxy = (event, context, callback) => {
  const request = {
    method: event.httpMethod,
    url: event.path,
    headers: event.headers,
    body: event.body,
    connection: {
      encrypted: event.headers['x-forwarded-proto'] === 'https',
    },
  };

  const response = {
    setHeader: (name, value) => {
      response.headers[name] = value;
    },
    writeHead: (statusCode, headers) => {
      response.statusCode = statusCode;
      response.headers = headers;
    },
    end: (body) => {
      addCorsHeaders(response.headers);
      callback(null, {
        statusCode: response.statusCode,
        headers: response.headers,
        body: body,
      });
    },
    headers: {},
  };

  // Add CORS headers to the initial response
  addCorsHeaders(response.headers);

  server.emit('request', request, response);
};