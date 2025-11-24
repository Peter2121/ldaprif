package middleware

import (
	"strings"

	"github.com/Bakemono-san/gofsen"
)

// AuthMiddleware middleware d'authentification basique
func AuthMiddleware() gofsen.MiddlewareFunc {
	return func(c *gofsen.Context) {
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

		// TODO: Implémenter la validation du token JWT ici
		if token == "" {
			c.Error(401, "Invalid token")
			return
		}

		// Continuer vers le handler suivant
		c.Next()
	}
}
