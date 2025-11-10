package handlers

import (
	"github.com/Bakemono-san/gofsen"
)

// HomeHandler handler pour la page d'accueil
func HomeHandler(c *gofsen.Context) {
	c.JSON(map[string]interface{}{
		"message":   "Bienvenue sur ldaprif!",
		"framework": "Gofsen",
		"version":   "1.2.0",
	})
}

// HealthHandler handler pour le health check
func HealthHandler(c *gofsen.Context) {
	c.JSON(map[string]interface{}{
		"status":    "OK",
		"service":   "ldaprif",
		"framework": "Gofsen",
	})
}

// StatusHandler handler pour le status de l'API
func StatusHandler(c *gofsen.Context) {
	c.JSON(map[string]interface{}{
		"api":     "v1",
		"status":  "running",
		"service": "ldaprif",
	})
}
