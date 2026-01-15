package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"main/handlers"
	"main/middleware"
	"main/types"
	"os"
	"strconv"

	"github.com/Bakemono-san/gofsen"
	"github.com/peter2121/ldap-mcli/ldap"
)

var LdapConfigFileName = "ldap.conf.json"
var MailConfigFileName = "mail.conf.json"
var AppConfigFileName = "app.conf.json"
var ConfigFilesPath []string = []string{"./", "/usr/local/etc/ldaprif/", "/etc/ldaprif/"}

var JWT_KEY []byte

//const JWT_KEY_LENGTH int = 64

/*
type ConfigApp struct {
	JwtKeyLength       int      `json:"jwt_key_length"`
	JwtAuthValidity    int      `json:"jwt_auth_validity"`
	JwtRefreshValidity int      `json:"jwt_refresh_validity"`
	WebPort            int      `json:"web_port"`
	CorsAllowOrigins   []string `json:"cors_allow_origins"`
}
*/

func ReadConfig[T ldap.ConfigLdap | ldap.ConfigMail | types.ConfigApp](config_file_path string) (*T, error) {
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

func FindConfigFile(file_name string) string {
	for _, path := range ConfigFilesPath {
		full_path := path + file_name
		if _, err := os.Stat(full_path); err == nil {
			return full_path
		}
	}
	return ""
}

func ReadConfigLdap(config_file_path string) (*ldap.ConfigLdap, error) {
	return ReadConfig[ldap.ConfigLdap](config_file_path)
}

func ReadConfigMail(config_file_path string) (*ldap.ConfigMail, error) {
	return ReadConfig[ldap.ConfigMail](config_file_path)
}

func ReadConfigApp(config_file_path string) (*types.ConfigApp, error) {
	return ReadConfig[types.ConfigApp](config_file_path)
}

func main() {

	ldap_config_file := FindConfigFile(LdapConfigFileName)
	if len(ldap_config_file) == 0 {
		fmt.Printf("FATAL: Cannot find ldap configuration file %s\n", LdapConfigFileName)
		return
	}
	fmt.Printf("Reading ldap configuration from file %s...\n", ldap_config_file)
	ldap_config, errlc := ReadConfigLdap(ldap_config_file)
	if errlc != nil {
		fmt.Printf("FATAL: Cannot read ldap configuration file %s: %v\n", LdapConfigFileName, errlc)
		return
	}
	if ldap_config == nil {
		fmt.Printf("FATAL: Cannot read ldap configuration file %s\n", LdapConfigFileName)
		return
	}

	mail_config_file := FindConfigFile(MailConfigFileName)
	if len(mail_config_file) == 0 {
		fmt.Printf("FATAL: Cannot find mail server configuration file %s\n", MailConfigFileName)
		return
	}
	fmt.Printf("Reading mail server configuration from file %s...\n", mail_config_file)
	mail_config, errmc := ReadConfigMail(mail_config_file)
	if errmc != nil {
		fmt.Printf("FATAL: Cannot read mail server configuration file %s: %v\n", MailConfigFileName, errmc)
		return
	}
	if mail_config == nil {
		fmt.Printf("FATAL: Cannot read mail server configuration file %s\n", MailConfigFileName)
		return
	}

	app_config_file := FindConfigFile(AppConfigFileName)
	if len(app_config_file) == 0 {
		fmt.Printf("FATAL: Cannot find application configuration file %s\n", AppConfigFileName)
		return
	}
	fmt.Printf("Reading application configuration from file %s...\n", app_config_file)
	app_config, errac := ReadConfigApp(app_config_file)
	if errac != nil {
		fmt.Printf("FATAL: Cannot read application configuration file %s: %v\n", AppConfigFileName, errac)
		return
	}
	if app_config == nil {
		fmt.Printf("FATAL: Cannot read application configuration file %s\n", AppConfigFileName)
		return
	}

	JWT_KEY = make([]byte, app_config.JwtKeyLength)
	rand.Read(JWT_KEY)

	ldap_data_handler := handlers.NewLdapDataHandler(ldap_config, mail_config, app_config, JWT_KEY)
	if ldap_data_handler == nil {
		log.Printf("FATAL: Cannot create LDAP data handler")
		return
	}

	app := gofsen.New()

	// Middlewares globaux
	app.Use(gofsen.Logger())
	app.Use(gofsen.Recovery())

	corsConfig := gofsen.CORSConfig{
		//AllowOrigins: []string{"*"},
		//AllowMethods: []string{"*"},
		//AllowOrigins: []string{"http://localhost:5173", "http://localhost:8080"},
		AllowOrigins: app_config.CorsAllowOrigins,
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
	}

	app.Use(gofsen.CORSWithConfig(corsConfig))

	app.Use(middleware.AuthMiddleware(ldap_data_handler))

	// Routes de base
	app.GET("/", handlers.HomeHandler)
	app.GET("/health", handlers.HealthHandler)
	app.POST("/auth", ldap_data_handler.AuthHandler)
	app.POST("/reauth", ldap_data_handler.ReAuthHandler)

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

	if (app_config.WebPort < 1) || (app_config.WebPort > 65535) {
		log.Printf("FATAL: Invalid web port in application configuration: %d", app_config.WebPort)
		return
	}
	port_str := strconv.Itoa(app_config.WebPort)
	if len(port_str) == 0 {
		log.Printf("FATAL: Invalid web port in application configuration: %d", app_config.WebPort)
	}
	// Démarrer le serveur
	log.Printf("🚀 Server %s is starting on port %s...", "ldaprif", port_str)
	app.Listen(port_str)
}
