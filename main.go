package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"main/handlers"
	"os"

	"github.com/Bakemono-san/gofsen"
	"github.com/peter2121/ldap-mcli/ldap"
)

var LdapConfigFileName = "ldap.conf.json"
var MailConfigFileName = "mail.conf.json"

var JWT_KEY []byte

const JWT_KEY_LENGTH int = 64

func ReadConfig[T ldap.ConfigLdap | ldap.ConfigMail](config_file_path string) (*T, error) {
	config_file, err := os.Open(config_file_path)
	if err != nil {
		return nil, err
	}
	defer config_file.Close()

	var config T
	config_file_content, _ := io.ReadAll(config_file)
	err = json.Unmarshal(config_file_content, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func ReadConfigLdap(config_file_path string) (*ldap.ConfigLdap, error) {
	return ReadConfig[ldap.ConfigLdap](config_file_path)
}

func ReadConfigMail(config_file_path string) (*ldap.ConfigMail, error) {
	return ReadConfig[ldap.ConfigMail](config_file_path)
}

func main() {

	ldap_config, errlc := ReadConfigLdap(LdapConfigFileName)
	if errlc != nil {
		fmt.Printf("FATAL: Cannot read ldap configuration file %s: %v\n", LdapConfigFileName, errlc)
		return
	}

	if ldap_config == nil {
		fmt.Printf("FATAL: Cannot read ldap configuration file %s\n", LdapConfigFileName)
		return
	}

	mail_config, errmc := ReadConfigMail(MailConfigFileName)
	if errmc != nil {
		fmt.Printf("FATAL: Cannot mail configuration file %s: %v\n", MailConfigFileName, errmc)
		return
	}

	if mail_config == nil {
		fmt.Printf("FATAL: Cannot read mail configuration file %s\n", MailConfigFileName)
		return
	}

	JWT_KEY = make([]byte, JWT_KEY_LENGTH)
	rand.Read(JWT_KEY)

	ldap_data_handler := handlers.NewLdapDataHandler(ldap_config, mail_config, JWT_KEY)
	if ldap_data_handler == nil {
		log.Printf("FATAL: Cannot create LDAP data handler")
	}

	// Créer une nouvelle instance Gofsen
	app := gofsen.New()

	// Middlewares globaux
	app.Use(gofsen.Logger())
	app.Use(gofsen.Recovery())

	corsConfig := gofsen.CORSConfig{
		//AllowOrigins: []string{"*"},
		//AllowMethods: []string{"*"},
		AllowOrigins: []string{"http://localhost:5173", "http://localhost:8080"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
	}

	app.Use(gofsen.CORSWithConfig(corsConfig))

	//app.Use(middleware.AuthMiddleware())

	// Routes de base
	app.GET("/", handlers.HomeHandler)
	app.GET("/health", handlers.HealthHandler)
	app.POST("/auth", ldap_data_handler.AuthHandler)

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
