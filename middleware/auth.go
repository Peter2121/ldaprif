package middleware

import (
	"main/handlers"

	"github.com/Bakemono-san/gofsen"
	//"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/request"
)

// AuthMiddleware middleware d'authentification basique
func AuthMiddleware(ldh *handlers.LdapDataHandler) gofsen.MiddlewareFunc {
	return func(c *gofsen.Context) {
		/*
			// Vérifier le header Authorization
			authHeader := c.Request.Header.Get("Authorization")

			if authHeader == "" {
				c.Error(401, "Missing Authorization header")
				return
			}

			// Vérifier le format Bearer token
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.Error(401, "Invalid Authorization format")
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
		*/
		if (c.Request.RequestURI != "/auth") && (c.Request.RequestURI != "/reauth") {
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
			// Continuer vers le handler suivant
			c.Next()
		} else {
			c.Next()
		}
	}
}
