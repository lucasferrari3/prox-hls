// © 2013 - 2016 Rob Wu <rob@robwu.nl>
// Released under the MIT license

var httpProxy = require("http-proxy");
var net = require("net");
var url = require("url");
var regexp_tld = require("./regexp-top-level-domain");
var getProxyForUrl = require("proxy-from-env").getProxyForUrl;
var zlib = require("zlib");

var help_text = {};
var _request_url;
var _mediaResourceUrl;
function showUsage(help_file, headers, response) {
  var isHtml = /\.html$/.test(help_file);
  headers["content-type"] = isHtml ? "text/html" : "text/plain";
  if (help_text[help_file] != null) {
    response.writeHead(200, headers);
    response.end(help_text[help_file]);
  } else {
    require("fs").readFile(help_file, "utf8", function (err, data) {
      if (err) {
        console.error(err);
        response.writeHead(500, headers);
        response.end();
      } else {
        help_text[help_file] = data;
        showUsage(help_file, headers, response); // Recursive call, but since data is a string, the recursion will end
      }
    });
  }
}

/**
 * Check whether the specified hostname is valid.
 *
 * @param hostname {string} Host name (excluding port) of requested resource.
 * @return {boolean} Whether the requested resource can be accessed.
 */
function isValidHostName(hostname) {
  return !!(
    regexp_tld.test(hostname) ||
    net.isIPv4(hostname) ||
    net.isIPv6(hostname)
  );
}

/**
 * Adds CORS headers to the response headers.
 *
 * @param headers {object} Response headers
 * @param request {ServerRequest}
 */
function withCORS(headers, request) {
  var corsMaxAge = request.corsAnywhereRequestState.corsMaxAge;
  if (corsMaxAge) {
    headers["access-control-max-age"] = corsMaxAge;
  }
  if (request.headers["access-control-request-method"]) {
    headers["access-control-allow-methods"] =
      request.headers["access-control-request-method"];
    delete request.headers["access-control-request-method"];
  }
  if (request.headers["access-control-request-headers"]) {
    headers["access-control-allow-headers"] =
      request.headers["access-control-request-headers"];
    delete request.headers["access-control-request-headers"];
  }

  //delete headers['access-control-allow-origin'];
  //delete headers['access-control-allow-methods'];

  //headers['access-control-allow-origin'] = "https://google.com";
  headers["access-control-allow-origin"] = "*"; // request.headers.origin || '*';
  //headers["x-frame-options"] = "*";//aggiunto 15 giugno 2020 md

  //headers['access-control-allow-headers'] = "x-requested-with, Content-Type, origin, authorization, accept, client-security-token, cache-control, postman-token, Accept-Ranges, Range";
  headers["access-control-expose-headers"] = "Content-Length, Content-Range";
  //headers['access-control-expose-headers'] = Object.keys(headers).join(',');
  //headers['content-security-policy'] = "default-src https: 'unsafe-eval' 'unsafe-inline' data: blob:; object-src 'self'; frame-ancestors https://canvas-taint.glitch.me/";
  //headers["x-frame-options"] = "*";
  return headers;
}

/**
 * Performs the actual proxy request.
 *
 * @param req {ServerRequest} Incoming http request
 * @param res {ServerResponse} Outgoing (proxied) http request
 * @param proxy {HttpProxy}
 */
function proxyRequest(req, res, proxy) {
  var location = req.corsAnywhereRequestState.location;
  req.url = location.path;

  var proxyOptions = {
    changeOrigin: false,
    prependPath: false,
    target: location,
    headers: {
      host: location.host
    },
    // HACK: Get hold of the proxyReq object, because we need it later.
    // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L144
    buffer: {
      pipe: function (proxyReq) {
        var proxyReqOn = proxyReq.on;
        // Intercepts the handler that connects proxyRes to res.
        // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L146-L158
        proxyReq.on = function (eventName, listener) {
          if (eventName !== "response") {
            return proxyReqOn.call(this, eventName, listener);
          }
          return proxyReqOn.call(this, "response", function (proxyRes) {
            if (onProxyResponse(proxy, proxyReq, proxyRes, req, res)) {
              try {
                listener(proxyRes);
              } catch (err) {
                // Wrap in try-catch because an error could occur:
                // "RangeError: Invalid status code: 0"
                // https://github.com/Rob--W/cors-anywhere/issues/95
                // https://github.com/nodejitsu/node-http-proxy/issues/1080

                // Forward error (will ultimately emit the 'error' event on our proxy object):
                // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L134
                proxyReq.emit("error", err);
              }
            }
          });
        };
        return req.pipe(proxyReq);
      }
    }
  };

  var proxyThroughUrl = req.corsAnywhereRequestState.getProxyForUrl(
    location.href
  );

  if (proxyThroughUrl) {
    proxyOptions.target = proxyThroughUrl;
    proxyOptions.toProxy = true;
    // If a proxy URL was set, req.url must be an absolute URL. Then the request will not be sent
    // directly to the proxied URL, but through another proxy.
    req.url = location.href;
  }

  // Start proxying the request
  try {
    // You can define here your custom logic to handle the request
    // and then proxy the request.

    proxy.web(req, res, proxyOptions);
  } catch (err) {
    proxy.emit("error", err, req, res);
  }
}

/**
 * This method modifies the response headers of the proxied response.
 * If a redirect is detected, the response is not sent to the client,
 * and a new request is initiated.
 *
 * client (req) -> CORS Anywhere -> (proxyReq) -> other server
 * client (res) <- CORS Anywhere <- (proxyRes) <- other server
 *
 * @param proxy {HttpProxy}
 * @param proxyReq {ClientRequest} The outgoing request to the other server.
 * @param proxyRes {ServerResponse} The response from the other server.
 * @param req {IncomingMessage} Incoming HTTP request, augmented with property corsAnywhereRequestState
 * @param req.corsAnywhereRequestState {object}
 * @param req.corsAnywhereRequestState.location {object} See parseURL
 * @param req.corsAnywhereRequestState.getProxyForUrl {function} See proxyRequest
 * @param req.corsAnywhereRequestState.proxyBaseUrl {string} Base URL of the CORS API endpoint
 * @param req.corsAnywhereRequestState.maxRedirects {number} Maximum number of redirects
 * @param req.corsAnywhereRequestState.redirectCount_ {number} Internally used to count redirects
 * @param res {ServerResponse} Outgoing response to the client that wanted to proxy the HTTP request.
 *
 * @returns {boolean} true if http-proxy should continue to pipe proxyRes to res.
 */
function onProxyResponse(proxy, proxyReq, proxyRes, req, res) {
  console.log(
    "This method modifies the response headers of the proxied response "
  );
  //console.log(req.corsAnywhereRequestState);
  var requestState = req.corsAnywhereRequestState;
  var statusCode = proxyRes.statusCode;

  if (!requestState.redirectCount_) {
    res.setHeader("x-request-url", requestState.location.href);
  }
  // Handle redirects
  if (
    statusCode === 301 ||
    statusCode === 302 ||
    statusCode === 303 ||
    statusCode === 307 ||
    statusCode === 308
  ) {
    console.log("Handle redirects");
    var locationHeader = proxyRes.headers.location;
    if (locationHeader) {
      locationHeader = url.resolve(requestState.location.href, locationHeader);

      if (statusCode === 301 || statusCode === 302 || statusCode === 303) {
        // Exclude 307 & 308, because they are rare, and require preserving the method + request body
        requestState.redirectCount_ = requestState.redirectCount_ + 1 || 1;
        if (requestState.redirectCount_ <= requestState.maxRedirects) {
          // Handle redirects within the server, because some clients (e.g. Android Stock Browser)
          // cancel redirects.
          // Set header for debugging purposes. Do not try to parse it!
          res.setHeader(
            "X-CORS-Redirect-" + requestState.redirectCount_,
            statusCode + " " + locationHeader
          );

          req.method = "GET";
          req.headers["content-length"] = "0";
          delete req.headers["content-type"];
          requestState.location = parseURL(locationHeader);

          // Remove all listeners (=reset events to initial state)
          req.removeAllListeners();

          // Remove the error listener so that the ECONNRESET "error" that
          // may occur after aborting a request does not propagate to res.
          // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L134
          proxyReq.removeAllListeners("error");
          proxyReq.once("error", function catchAndIgnoreError() {});
          proxyReq.abort();

          // Initiate a new proxy request.
          proxyRequest(req, res, proxy);
          return false;
        }
      }
      proxyRes.headers.location =
        requestState.proxyBaseUrl + "/" + locationHeader;
    }
  }

  // Strip cookies
  delete proxyRes.headers["set-cookie"];
  delete proxyRes.headers["set-cookie2"];

  proxyRes.headers["x-final-url"] = requestState.location.href;
  withCORS(proxyRes.headers, req);

  return true;
}

function addHostToMasterFile(body, req) {
  var masterFile = "";
  var codeSandboxAppUrl = process.env.SANDBOX_URL;

  if (body.indexOf("master-file") < 0) {
    return body;
  }
  console.log("Writing modified data (pvideo master-file path) !");

  var matchMasterFile = body.match(/(?:("master-file"\s+):\s+"(\/.+.html)")/i);
  var matchOriginalMasterFile = body.match(
    /"master-file"\s*:\s*"(.*\/).*.html/i
  );

  if (!matchMasterFile || !matchMasterFile[2]) {
    console.log("Not found masterfile ");
    return "";
  }

  var matchHostname = body.match(
    /(("hostName"):"(https:\/\/[A-Za-z0-9.-]+)")/i
  );
  if (!matchHostname) {
    masterFile =
      codeSandboxAppUrl +
      "https://" +
      req.corsAnywhereRequestState.location.host +
      matchMasterFile[2];
    _mediaResourceUrl =
      "https://" +
      req.corsAnywhereRequestState.location.host +
      matchMasterFile[2].substring(0, matchMasterFile[2].lastIndexOf("/") + 1);
  } else {
    masterFile = codeSandboxAppUrl + matchHostname[3] + matchMasterFile[2];
    _mediaResourceUrl = matchHostname[3] + matchOriginalMasterFile[1];
  }
  //

  body = body.replace(matchMasterFile[2], masterFile);
  body = body.replace(
    masterFile,
    masterFile + '",\n\t\t"media-resources-url" : "' + _mediaResourceUrl
  );
  return body;
}

function addMediaResourcesUrl(body, req) {
  if (body.indexOf('id="media-resources-url"') < 0) {
    return body;
  }
  console.log("Writing modified data (pvideo media-resources-url) !");

  let href = req.corsAnywhereRequestState.location.href.replace(
    /\/[^/]*$/,
    "/"
  );
  return body.replace(
    /<base href="([^"]*)" id="media-resources-url">/,
    `<base href="${href}" id="media-resources-url">`
  );
}

/**
 * @param req_url {string} The requested URL (scheme is optional).
 * @return {object} URL parsed using url.parse
 */
function parseURL(req_url) {
  var match = req_url.match(
    /^(?:(https?:)?\/\/)?(([^\/?]+?)(?::(\d{0,5})(?=[\/?]|$))?)([\/?][\S\s]*|$)/i
  );
  //                              ^^^^^^^          ^^^^^^^^      ^^^^^^^                ^^^^^^^^^^^^
  //                            1:protocol       3:hostname     4:port                 5:path + query string
  //                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  //                                            2:host
  if (!match) {
    return null;
  }
  if (!match[1]) {
    // Scheme is omitted.
    if (req_url.lastIndexOf("//", 0) === -1) {
      // "//" is omitted.
      req_url = "//" + req_url;
    }
    req_url = (match[4] === "443" ? "https:" : "http:") + req_url;
  }
  return url.parse(req_url);
}

// Request handler factory
function getHandler(options, proxy) {
  var corsAnywhere = {
    getProxyForUrl: getProxyForUrl, // Function that specifies the proxy to use
    maxRedirects: 5, // Maximum number of redirects to be followed.
    originBlacklist: [], // Requests from these origins will be blocked.
    originWhitelist: [], // If non-empty, requests not from an origin in this list will be blocked.
    checkRateLimit: null, // Function that may enforce a rate-limit by returning a non-empty string.
    redirectSameOrigin: false, // Redirect the client to the requested URL for same-origin requests.
    requireHeader: null, // Require a header to be set?
    removeHeaders: [], // Strip these request headers.
    setHeaders: {}, // Set these request headers.
    corsMaxAge: 0, // If set, an Access-Control-Max-Age header with this value (in seconds) will be added.
    helpFile: __dirname + "/help.txt"
  };

  Object.keys(corsAnywhere).forEach(function (option) {
    if (Object.prototype.hasOwnProperty.call(options, option)) {
      corsAnywhere[option] = options[option];
    }
  });

  // Convert corsAnywhere.requireHeader to an array of lowercase header names, or null.
  if (corsAnywhere.requireHeader) {
    if (typeof corsAnywhere.requireHeader === "string") {
      corsAnywhere.requireHeader = [corsAnywhere.requireHeader.toLowerCase()];
    } else if (
      !Array.isArray(corsAnywhere.requireHeader) ||
      corsAnywhere.requireHeader.length === 0
    ) {
      corsAnywhere.requireHeader = null;
    } else {
      corsAnywhere.requireHeader = corsAnywhere.requireHeader.map(function (
        headerName
      ) {
        return headerName.toLowerCase();
      });
    }
  }
  var hasRequiredHeaders = function (headers) {
    return (
      !corsAnywhere.requireHeader ||
      corsAnywhere.requireHeader.some(function (headerName) {
        return Object.hasOwnProperty.call(headers, headerName);
      })
    );
  };

  return function (req, res) {
    _request_url = req.url.slice(1);

    req.corsAnywhereRequestState = {
      getProxyForUrl: corsAnywhere.getProxyForUrl,
      maxRedirects: corsAnywhere.maxRedirects,
      corsMaxAge: corsAnywhere.corsMaxAge
    };

    var cors_headers = withCORS({}, req);
    if (req.method === "OPTIONS") {
      // Pre-flight request. Reply successfully:
      res.writeHead(200, cors_headers);
      res.end();
      return;
    }

    var location = parseURL(req.url.slice(1));

    if (!location) {
      // Invalid API call. Show how to correctly use the API
      showUsage(corsAnywhere.helpFile, cors_headers, res);
      return;
    }

    if (location.port > 65535) {
      // Port is higher than 65535
      res.writeHead(400, "Invalid port", cors_headers);
      res.end("Port number too large: " + location.port);
      return;
    }

    if (!/^\/https?:/.test(req.url) && !isValidHostName(location.hostname)) {
      // Don't even try to proxy invalid hosts (such as /favicon.ico, /robots.txt)
      res.writeHead(404, "Invalid host", cors_headers);
      res.end("Invalid host: " + location.hostname);
      return;
    }

    if (!hasRequiredHeaders(req.headers)) {
      res.writeHead(400, "Header required", cors_headers);
      res.end(
        "Missing required request header. Must specify one of: " +
          corsAnywhere.requireHeader
      );
      return;
    }

    var origin = req.headers.origin || "";
    if (corsAnywhere.originBlacklist.indexOf(origin) >= 0) {
      res.writeHead(403, "Forbidden", cors_headers);
      res.end(
        'The origin "' +
          origin +
          '" was blacklisted by the operator of this proxy.'
      );
      return;
    }

    if (
      corsAnywhere.originWhitelist.length &&
      corsAnywhere.originWhitelist.indexOf(origin) === -1
    ) {
      res.writeHead(403, "Forbidden", cors_headers);
      res.end(
        'The origin "' +
          origin +
          '" was not whitelisted by the operator of this proxy.'
      );
      return;
    }

    var rateLimitMessage =
      corsAnywhere.checkRateLimit && corsAnywhere.checkRateLimit(origin);
    if (rateLimitMessage) {
      res.writeHead(429, "Too Many Requests", cors_headers);
      res.end(
        'The origin "' +
          origin +
          '" has sent too many requests.\n' +
          rateLimitMessage
      );
      return;
    }

    if (
      corsAnywhere.redirectSameOrigin &&
      origin &&
      location.href[origin.length] === "/" &&
      location.href.lastIndexOf(origin, 0) === 0
    ) {
      // Send a permanent redirect to offload the server. Badly coded clients should not waste our resources.
      cors_headers.vary = "origin";
      cors_headers["cache-control"] = "private";
      cors_headers.location = location.href;
      res.writeHead(301, "Please use a direct request", cors_headers);
      res.end();
      return;
    }

    var isRequestedOverHttps =
      req.connection.encrypted ||
      /^\s*https/.test(req.headers["x-forwarded-proto"]);
    var proxyBaseUrl =
      (isRequestedOverHttps ? "https://" : "http://") + req.headers.host;

    //console.log("rimuovo tutti gli header della req che voglio levare");
    corsAnywhere.removeHeaders.forEach(function (header) {
      delete req.headers[header];
    });
    //console.log("aggiungo tutti gli header alla req che voglio aggiungere (x-frame-options) per esempio");
    Object.keys(corsAnywhere.setHeaders).forEach(function (header) {
      req.headers[header] = corsAnywhere.setHeaders[header];
    });

    //req.headers["x-frame-options"] = '*';
    //req.headers["access-control-allow-origin"] = '*';
    //console.log("Header della richiesta proxata:");
    //console.log(req.headers);
    req.corsAnywhereRequestState.location = location;
    req.corsAnywhereRequestState.proxyBaseUrl = proxyBaseUrl;

    //prima esegue controlli e manipolazioni della richiesta
    proxyRequest(req, res, proxy);
  };
}

function returnBodyAsString(proxyRes, originalBody) {
  let str = "";
  console.log("content-encoding", proxyRes.headers["content-encoding"]);
  if (proxyRes.headers["content-encoding"] === "gzip") {
    str = zlib.gunzipSync(Buffer.concat(originalBody)).toString("utf8");
  } else {
    str = Buffer.concat(originalBody).toString("utf8");
  }

  return str;
}

// Create server with default and given values
// Creator still needs to call .listen()
exports.createServer = function createServer(options) {
  options = options || {};

  // Default options:
  var httpProxyOptions = {
    xfwd: true // Append X-Forwarded-* headers
  };
  // Allow user to override defaults and add own options
  if (options.httpProxyOptions) {
    Object.keys(options.httpProxyOptions).forEach(function (option) {
      httpProxyOptions[option] = options.httpProxyOptions[option];
    });
  }
  //
  // Create a proxy server with custom application logic
  // var proxy = httpProxy.createProxyServer(httpProxyOptions);
  //
  console.log(options.httpProxyOptions); //{xfwd:false, selfHandleResponse:true}
  var proxy = httpProxy.createServer(httpProxyOptions);
  var requestHandler = getHandler(options, proxy);
  var server;
  //
  // Create your custom server and just call `proxy.web()` to proxy
  // a web request to the target passed in the options
  //

  if (options.httpsOptions) {
    server = require("https").createServer(
      options.httpsOptions,
      requestHandler
    );
  } else {
    server = require("http").createServer(requestHandler);
  }

  //
  // Listen for the `proxyRes` event on `proxy`.
  //
  proxy.on("proxyRes", function (proxyRes, req, res) {
    //console.log('RAW Response from the target', JSON.stringify(proxyRes.headers, true, 2));
    if (
      proxyRes.headers["content-type"] &&
      proxyRes.headers["content-type"].includes("text/html")
    ) {
      const end = res.end;
      const writeHead = res.writeHead;
      let writeHeadArgs;
      var body;
      var originalBody = [];
      proxyRes
        .on("data", (chunk) => {
          originalBody.push(Buffer.from(chunk, "utf8"));
        })
        .on("end", () => {
          var dataStr = returnBodyAsString(proxyRes, originalBody);
          var html = addHostToMasterFile(dataStr, req);
          html = addMediaResourcesUrl(html, req);
          // Calling gzip method
          body = zlib.gzipSync(html);
        });

      // Defer write and writeHead
      res.write = () => {};
      res.writeHead = (...args) => {
        writeHeadArgs = args;
      };

      // Update user response at the end
      res.end = () => {
        const output = body; // some function to manipulate body
        if (output) res.setHeader("content-length", output.length);
        res.setHeader("content-encoding", "gzip");
        writeHead.apply(res, writeHeadArgs);
        end.apply(res, [output]);
      };
    } else {
      //proxyRes.pipe(res);
    }
  });

  // To modify the proxy connection before data is sent, you can listen
  // for the 'proxyReq' event. When the event is fired, you will receive
  // the following arguments:
  // (http.ClientRequest proxyReq, http.IncomingMessage req,
  //  http.ServerResponse res, Object options). This mechanism is useful when
  // you need to modify the proxy request before the proxy connection
  // is made to the target.
  //
  proxy.on("proxyReq", function (proxyReq, req, res, options) {
    //proxyReq.setHeader('X-Special-Proxy-Header', 'foobar');
    //proxyReq.setHeader("Origin", "https://i1c6i.sse.codesandbox.io");
    //proxyReq.setHeader("Referer", "https://i1c6i.sse.codesandbox.io");
    proxyReq.setHeader("x-frame-options", "*");
    //proxyReq.setHeader("Sec-Fetch-Site", "cross-site");
    //proxyReq.setHeader("Sec-Fetch-User", "?1");
    //proxyReq.setHeader("Connection", "Keep-Alive");
    //proxyReq.setHeader("accept-encoding", "gzip, deflate, br");
    console.log(
      " This listener can be used to change proxyReq before data is sent !"
    );
    //proxyReq.headers = proxyReq.headers || {}
    //proxyReq.headers['x-frame-options'] = '*';
    //proxyReq.headers['Connection'] = 'Keep-Alive';
    //console.log(proxyReq);
  });

  // When the server fails, just show a 404 instead of Internal server error
  proxy.on("error", function (err, req, res) {
    console.log("Errore " + err);
    if (res.headersSent) {
      // This could happen when a protocol error occurs when an error occurs
      // after the headers have been received (and forwarded). Do not write
      // the headers because it would generate an error.
      return;
    }

    // When the error occurs after setting headers but before writing the response,
    // then any previously set headers must be removed.
    var headerNames = res.getHeaderNames
      ? res.getHeaderNames()
      : Object.keys(res._headers || {});
    headerNames.forEach(function (name) {
      res.removeHeader(name);
    });

    res.writeHead(404, { "Access-Control-Allow-Origin": "*" });
    res.end("Not found because of proxy error: " + err);
  });

  return server;
};
