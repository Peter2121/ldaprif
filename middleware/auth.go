package middleware

import (
	"net/http"

	"main/handlers"

	"github.com/Bakemono-san/gofsen"
	"github.com/golang-jwt/jwt/v5/request"
)

// Routes reachable without a token. Matched on the URL path (RequestURI would include the query string).
var publicPaths = map[string]bool{
	"/health": true,
	"/auth":   true,
	"/reauth": true,
}

// AuthMiddleware requires a valid admin bearer token on every route but the public ones.
func AuthMiddleware(ldh *handlers.LdapDataHandler) gofsen.MiddlewareFunc {
	return func(c *gofsen.Context) {
		if publicPaths[c.Request.URL.Path] {
			c.Next()
			return
		}
		token, err := request.BearerExtractor{}.ExtractToken(c.Request)
		if err != nil {
			c.Error(401, "Invalid Authorization format")
			return
		}

		if token == "" {
			c.Error(401, "Empty Authorization token")
			return
		}

		if !ldh.ValidateAuthToken(c, token) {
			c.Error(401, "Invalid Authorization token")
			return
		}
		c.Next()
	}
}

// BodyLimit caps the request body so that a client cannot exhaust memory with a huge JSON document.
func BodyLimit(maxBytes int64) gofsen.MiddlewareFunc {
	return func(c *gofsen.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.ResponseWriter, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
