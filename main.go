package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"main/handlers"
	"main/middleware"
	"os"

	"github.com/Bakemono-san/gofsen"
	"github.com/peter2121/ldap-mcli/ldap"
)

var LdapConfigFileName = "ldap.conf.json"

func ReadConfig(config_file_path string) (*ldap.Config, error) {
	config_file, err := os.Open(config_file_path)
	if err != nil {
		return nil, err
	}
	defer config_file.Close()

	var config ldap.Config
	config_file_content, _ := io.ReadAll(config_file)
	err = json.Unmarshal(config_file_content, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func main() {

	config, err := ReadConfig(LdapConfigFileName)
	if (err != nil) || (config == nil) {
		fmt.Printf("FATAL: Cannot read configuration file %s: %v\n", LdapConfigFileName, err)
		return
	}

	ldap_data_handler := handlers.NewLdapDataHandler(config)
	if ldap_data_handler == nil {
		log.Printf("FATAL: Cannot create LDAP data handler")
	}

	// Créer une nouvelle instance Gofsen
	app := gofsen.New()

	// Middlewares globaux
	app.Use(gofsen.Logger())
	app.Use(gofsen.Recovery())

	app.Use(middleware.AuthMiddleware())

	// Routes de base
	app.GET("/", handlers.HomeHandler)
	app.GET("/health", handlers.HealthHandler)

	// Groupes d'API
	api := app.Group("/api/v1")
	api.GET("/status", handlers.StatusHandler)

	api.GET("/users", ldap_data_handler.UsersHandler)
	api.GET("/users/:uid", ldap_data_handler.UserHandler)
	api.DELETE("/users/:uid", ldap_data_handler.UserHandler)
	api.PUT("/users/:uid", ldap_data_handler.UserHandler)
	api.POST("/users", ldap_data_handler.CreateUserHandler)
	api.GET("/groups", ldap_data_handler.GroupsHandler)
	api.GET("/groups/:gid", ldap_data_handler.GroupHandler)
	api.DELETE("/groups/:gid", ldap_data_handler.GroupHandler)
	api.PUT("/groups/:gid", ldap_data_handler.GroupHandler)
	api.POST("/groups", ldap_data_handler.CreateGroupHandler)

	// Afficher les routes
	app.PrintRoutes()

	// Démarrer le serveur
	log.Printf("🚀 Serveur %s démarré sur http://localhost:8080", "ldaprif")
	app.Listen("8080")
	//log.Printf("End")
}
