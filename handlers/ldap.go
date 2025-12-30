package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/Bakemono-san/gofsen"
	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/go-utils/utils/slice"
	"github.com/golang-jwt/jwt/v5"
	"github.com/peter2121/ldap-mcli/ldap"
	"github.com/pierrec/xxHash/xxHash32"
)

type LdapDataHandler struct {
	LdapConfig *ldap.ConfigLdap
	MailConfig *ldap.ConfigMail
	Opts       []ldap.ClientOption
	//LdapClient    *ldap.Client
	JwtSignKey    []byte
	AuthTokens    []string
	RefreshTokens []string
}

type JwtAuthData struct {
	IsAdmin string `json:"iad,omitempty"`
	jwt.RegisteredClaims
}

type JwtRefrData struct {
	jwt.RegisteredClaims
}

type JwtResponse struct {
	JwtAuthToken    string `json:"auth_token"`
	JwtRefreshToken string `json:"refresh_token"`
}

func (m JwtAuthData) Validate() error {
	if strings.ToUpper(m.IsAdmin) != "YES" {
		return fmt.Errorf("Must be domain admin")
	}
	return nil
}

const JWT_AUTH_VALIDITY_MINS = 20
const JWT_REFRESH_VALIDITY_MINS = 1440
const JWT_REFRESH_SUBJECT string = "Refresh"

const WEB_CLIENT string = "web"
const MOBILE_CLIENT string = "mobile"
const DESKTOP_CLIENT string = "desktop"

var CLIENTS = []string{WEB_CLIENT, MOBILE_CLIENT, DESKTOP_CLIENT}

func NewLdapDataHandler(ldap_config *ldap.ConfigLdap, mail_config *ldap.ConfigMail, jsik []byte, opts ...ldap.ClientOption) *LdapDataHandler {
	ldap_data_handler := LdapDataHandler{}
	ldap_data_handler.LdapConfig = ldap_config
	ldap_data_handler.MailConfig = mail_config
	ldap_data_handler.Opts = opts
	ldap_data_handler.JwtSignKey = jsik
	ldap_data_handler.AuthTokens = make([]string, 0)
	ldap_data_handler.RefreshTokens = make([]string, 0)
	return &ldap_data_handler
	//ldap_data_handler.LdapClient = nil
	/*
		ldap_data_handler.LdapClient = ldap.NewClient(ldap_config, mail_config, opts...)
		if ldap_data_handler.LdapClient != nil {
			return &ldap_data_handler
		} else {
			return nil
		}
	*/
}

func (ldh *LdapDataHandler) AuthHandler(c *gofsen.Context) {
	type AuthData struct {
		UserName string `json:"username"`
		Password string `json:"password"`
		Client   string `json:"client"`
	}
	var auth_data = AuthData{}
	if err := c.BindJSON(&auth_data); err != nil {
		c.Status(400).JSON(map[string]any{
			"status": "error",
			"error":  "Invalid JSON",
		})
		return
	}
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  "Cannot create LDAP client",
		})
		return
	}
	user, errauth := ldap_client.AuthenticateUser(auth_data.UserName, auth_data.Password)
	if errauth != nil {
		c.Status(401).JSON(map[string]any{
			"status": "error",
			"error":  errauth.Message,
		})
		return
	}
	if user == nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  "Cannot get user object from LDAP",
		})
		return
	}
	auth_token, refresh_token, strerrtok := GetTokens(c.Request.URL.Host, auth_data.UserName, ldh.LdapConfig.MailDomain, auth_data.Client, user.DomainAdmin)
	if len(strerrtok) > 0 {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  strerrtok,
		})
		return
	}
	if (auth_token == nil) || (refresh_token == nil) {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  "Cannot get authentication tokens",
		})
		return
	}

	auth_token_signed, errsigna := auth_token.SignedString(ldh.JwtSignKey)
	if errsigna != nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  errsigna.Error(),
		})
		return
	}
	ldh.AuthTokens = append(ldh.AuthTokens, auth_token_signed)

	refresh_token_signed, errsignr := refresh_token.SignedString(ldh.JwtSignKey)
	if errsignr != nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  errsignr.Error(),
		})
		return
	}
	ldh.RefreshTokens = append(ldh.RefreshTokens, refresh_token_signed)

	jwt_response := JwtResponse{
		JwtAuthToken:    auth_token_signed,
		JwtRefreshToken: refresh_token_signed,
	}
	c.JSON(jwt_response)
}

func (ldh *LdapDataHandler) ReAuthHandler(c *gofsen.Context) {
	type ReAuthData struct {
		RefreshToken string `json:"refresh_token"`
		Client       string `json:"client"`
	}
	var reauth_data = ReAuthData{}
	if err := c.BindJSON(&reauth_data); err != nil {
		c.Status(400).JSON(map[string]any{
			"status": "error",
			"error":  "Invalid JSON",
		})
		return
	}

	refresh_token_string := reauth_data.RefreshToken
	if len(refresh_token_string) == 0 {
		c.Status(400).JSON(map[string]any{
			"status": "error",
			"error":  "Cannot get reauthentication token from data sent",
		})
	}

	ok, claims := ldh.ValidateReAuthToken(c, refresh_token_string)
	if (!ok) || (claims == nil) {
		c.Status(400).JSON(map[string]any{
			"status": "error",
			"error":  "Invalid refresh token",
		})
		return
	}

	auth_token, refresh_token, strerrtok := GetTokens(c.Request.URL.Host, claims.Audience[1], ldh.LdapConfig.MailDomain, claims.Audience[0], claims.IsAdmin)
	if len(strerrtok) > 0 {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  strerrtok,
		})
		return
	}
	if (auth_token == nil) || (refresh_token == nil) {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  "Cannot get authentication tokens",
		})
		return
	}

	auth_token_signed, errsigna := auth_token.SignedString(ldh.JwtSignKey)
	if errsigna != nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  errsigna.Error(),
		})
		return
	}
	ldh.AuthTokens = append(ldh.AuthTokens, auth_token_signed)

	refresh_token_signed, errsignr := refresh_token.SignedString(ldh.JwtSignKey)
	if errsignr != nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  errsignr.Error(),
		})
		return
	}
	ldh.RefreshTokens = append(ldh.RefreshTokens, refresh_token_signed)

	jwt_response := JwtResponse{
		JwtAuthToken:    auth_token_signed,
		JwtRefreshToken: refresh_token_signed,
	}
	c.JSON(jwt_response)
}

func (ldh *LdapDataHandler) ValidateReAuthToken(c *gofsen.Context, reauth_token_string string) (bool, *JwtAuthData) {
	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		reauth_token_string,
		&claims,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return ldh.JwtSignKey, nil
		},
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithLeeway(1*time.Minute),
		jwt.WithAudience(CLIENTS...),
		jwt.WithIssuer(c.Request.URL.Host),
		jwt.WithSubject(JWT_REFRESH_SUBJECT),
	)
	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return false, nil
	}

	if !token.Valid {
		log.Printf("Token is invalid")
		return false, nil
	}

	if len(claims.Audience) < 2 {
		log.Printf("No username in refresh token audience claim")
		return false, nil
	}

	username := claims.Audience[1]
	if len(username) == 0 {
		log.Printf("Empty username in refresh token audience claim")
		return false, nil
	}
	var user *ldap.User
	var erru *errors.Error

	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		log.Printf("Cannot create LDAP client")
		return false, nil
	}

	if strings.Contains(username, "@") {
		user, erru = ldap_client.Users.GetByEmail(username)
	} else {
		user, erru = ldap_client.Users.GetByUid(username)
	}

	if erru != nil {
		log.Printf("Cannot find user %s in LDAP: %v", username, erru)
		return false, nil
	}

	if strings.ToUpper(user.DomainAdmin) != "YES" {
		log.Printf("User %s is not admin", username)
		return false, nil
	}

	ret_claims := JwtAuthData{user.DomainAdmin, claims}
	return true, &ret_claims
}

func (ldh *LdapDataHandler) ValidateAuthToken(c *gofsen.Context, auth_token_string string) bool {
	claims := JwtAuthData{}
	token, err := jwt.ParseWithClaims(
		auth_token_string,
		&claims,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return ldh.JwtSignKey, nil
		},
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithLeeway(1*time.Minute),
		jwt.WithAudience(CLIENTS...),
		jwt.WithIssuer(c.Request.URL.Host),
		jwt.WithSubject(ldh.LdapConfig.MailDomain),
	)
	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return false
	}

	if !token.Valid {
		log.Printf("Token is invalid")
		return false
	}

	// TODO: add support for non-admin tokens
	/*
		if strings.ToUpper(claims.IsAdmin) != "YES" {
			...
		}
	*/
	return true
}

func GetTokens(hostname, username, maildomain, client, isadmin string) (*jwt.Token, *jwt.Token, string) {
	hash_fab := xxHash32.New(0)
	timestamp_iss := time.Now()
	timestamp_exp_auth := timestamp_iss.Add(time.Duration(time.Minute * JWT_AUTH_VALIDITY_MINS))
	timestamp_exp_refresh := timestamp_iss.Add(time.Duration(time.Minute * JWT_REFRESH_VALIDITY_MINS))
	timestamp_nbf_refresh := timestamp_iss.Add(time.Duration(time.Minute * (JWT_AUTH_VALIDITY_MINS / 2)))
	//timestamp_nbf_refresh := timestamp_iss.Add(time.Duration(time.Minute * 2))
	hash_fab.Write([]byte(timestamp_iss.Format("2006-01-02T15:04:05Z07:00")))
	hash_fab.Write([]byte(hostname))
	hash_fab.Write([]byte(username))
	id := fmt.Sprintf("%X", hash_fab.Sum32())

	//log.Printf("Issued: %v\n", *jwt.NewNumericDate(timestamp_iss))
	//log.Printf("Expires: %v\n", *jwt.NewNumericDate(timestamp_exp_auth))
	//log.Printf("Start refresh: %v\n", *jwt.NewNumericDate(timestamp_nbf_refresh))
	//log.Printf("Expires refresh: %v\n", *jwt.NewNumericDate(timestamp_exp_refresh))

	jwt_auth_data := JwtAuthData{
		isadmin,
		jwt.RegisteredClaims{
			ID:        id,
			Issuer:    hostname,
			Subject:   maildomain,
			Audience:  []string{client, username},
			IssuedAt:  jwt.NewNumericDate(timestamp_iss),
			ExpiresAt: jwt.NewNumericDate(timestamp_exp_auth),
		},
	}

	jwt_refresh_data := JwtRefrData{
		jwt.RegisteredClaims{
			ID:        id,
			Issuer:    hostname,
			Subject:   JWT_REFRESH_SUBJECT,
			Audience:  []string{client, username},
			IssuedAt:  jwt.NewNumericDate(timestamp_iss),
			ExpiresAt: jwt.NewNumericDate(timestamp_exp_refresh),
			NotBefore: jwt.NewNumericDate(timestamp_nbf_refresh),
		},
	}

	auth_token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt_auth_data)
	refresh_token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt_refresh_data)

	return auth_token, refresh_token, ""
}

func (ldh *LdapDataHandler) UsersHandler(c *gofsen.Context) {
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		c.Status(500).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "Cannot create LDAP client",
		})
		return
	}
	users, _ := ldap_client.Users.GetAll()
	c.JSON(users)
}

func (ldh *LdapDataHandler) UserHandler(c *gofsen.Context) {
	var user, user_old *ldap.User = nil, nil
	var err *errors.Error
	uid := c.Param("uid")
	srch_by_mail := strings.Contains(uid, "@")
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		c.Status(500).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "Cannot create LDAP client",
		})
		return
	}
	switch c.Request.Method {
	case "GET":
		if srch_by_mail {
			user, err = ldap_client.Users.GetByEmail(uid)
		} else {
			user, err = ldap_client.Users.GetByUid(uid)
		}
		if err == nil {
			if user != nil {
				c.JSON(user)
			}
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  err.Message,
			})
		}
	case "PUT":
		if srch_by_mail {
			user_old, err = ldap_client.Users.GetByEmail(uid)
		} else {
			user_old, err = ldap_client.Users.GetByUid(uid)
		}
		// TODO: manage user creation if user is not found
		if err != nil {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  err.Message,
			})
		}
		if user_old == nil {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Cannot find existing user to modify",
			})
		}
		if err := c.BindJSON(&user); err != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Invalid JSON",
			})
			return
		}
		errmod := ldap_client.Users.ModifyUser(*user, *user_old)
		if errmod != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errmod.Message,
			})
			return
		}
		user_mod, errum := ldap_client.Users.GetByEmail(user.Mail)
		if (errum == nil) && (user_mod != nil) {
			c.JSON(user_mod)
			return
		} else if errum != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errum.Message,
			})
			return
		} else {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Cannot get modified user from LDAP",
			})
			return
		}
	case "DELETE":
		if srch_by_mail {
			err = ldap_client.Users.DeleteByEmail(uid)
		} else {
			err = ldap_client.Users.DeleteByUid(uid)
		}
		if err == nil {
			c.Status(204)
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  err.Message,
			})
		}
	}
}

func (ldh *LdapDataHandler) CreateUserHandler(c *gofsen.Context) {
	var user ldap.User
	if err := c.BindJSON(&user); err != nil {
		c.Status(400).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "Invalid JSON",
		})
		return
	}
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  "Cannot create LDAP client",
		})
		return
	}
	errc := ldap_client.Users.Create(user)
	if errc == nil {
		c.Status(201).JSON(user)
	} else {
		c.JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  errc.Message,
		})
	}
}

func (ldh *LdapDataHandler) GroupsHandler(c *gofsen.Context) {
	var have_gss bool = false
	var have_gsm bool = false
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  "Cannot create LDAP client",
		})
		return
	}
	groupss, _ := ldap_client.GroupsSec.GetAll()
	if len(groupss) > 0 {
		have_gss = true
	}
	/*
		for _, group := range groupss {
			fmt.Printf("Security Group: %s\n", group.Cn)
		}
	*/
	groupsm, _ := ldap_client.GroupsMail.GetAll()
	if len(groupsm) > 0 {
		have_gsm = true
	}
	/*
		for _, group := range groupsm {
			fmt.Printf("Distribution Group: %s (%s)\n", group.Cn, group.Mail)
		}
	*/
	var str_gss string = ""
	var str_gsm string = ""

	if have_gss {
		byte_gss, err_gss := json.Marshal(groupss)
		if err_gss == nil {
			str_gss = strings.Trim(string(byte_gss), "[]")
		}
	}

	if have_gsm {
		byte_gsm, err_gsm := json.Marshal(groupsm)
		if err_gsm == nil {
			str_gsm = strings.Trim(string(byte_gsm), "[]")
		}
	}

	var result string = "[ "
	if len(str_gss) > 0 {
		result = result + str_gss
		if len(str_gsm) > 0 {
			result = result + ", " + str_gsm
		}
	} else {
		result = result + str_gsm
	}
	result = result + " ]"

	var jres []map[string]any
	erruj := json.Unmarshal([]byte(result), &jres)
	if erruj == nil {
		c.JSON(jres)
	} else {
		fmt.Printf("Error unmarshaling concatenated result: %v\n", erruj)
	}
}

func (ldh *LdapDataHandler) GroupHandler(c *gofsen.Context) {
	gid := c.Param("gid")
	srch_by_mail := strings.Contains(gid, "@")

	var group_mail *ldap.GroupMail = nil
	var errgm *errors.Error = nil
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  "Cannot create LDAP client",
		})
		return
	}
	switch c.Request.Method {
	case "GET":
		if !srch_by_mail {
			group_sec, errgs := ldap_client.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
			if (errgs == nil) && (group_sec != nil) {
				c.JSON(group_sec)
				return
			}
		}
		if srch_by_mail {
			group_mail, errgm = ldap_client.GroupsMail.GetOne(ldap.MailAttr, gid, "")
		} else {
			group_mail, errgm = ldap_client.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
		}
		if errgm == nil {
			if group_mail != nil {
				c.JSON(group_mail)
			}
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errgm.Message,
			})
		}
	case "PUT":
		var group_sec *ldap.GroupSec = nil
		if !srch_by_mail {
			group_old, errgs := ldap_client.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
			if (errgs == nil) && (group_old != nil) {
				if err := c.BindJSON(&group_sec); err != nil {
					c.Status(400).JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  "Invalid JSON",
					})
					return
				}
				errmod := ldap_client.GroupsSec.ModifyGroup(*group_sec, *group_old)
				if errmod != nil {
					c.Status(400).JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  errmod.Message,
					})
					return
				}
				group_mod, errgsm := ldap_client.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
				if (errgsm == nil) && (group_mod != nil) {
					c.JSON(group_mod)
					return
				} else if errgsm != nil {
					c.Status(400).JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  errgsm.Message,
					})
					return
				} else {
					c.Status(400).JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  "Cannot get modified group from LDAP",
					})
					return
				}
			} else {
				group_old, errgs := ldap_client.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
				if (errgs == nil) && (group_old != nil) {
					if err := c.BindJSON(&group_mail); err != nil {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "Invalid JSON",
						})
						return
					}
					errmod := ldap_client.GroupsMail.ModifyGroup(*group_mail, *group_old)
					if errmod != nil {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  errmod.Message,
						})
						return
					}
					group_mod, errgsm := ldap_client.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
					if (errgsm == nil) && (group_mod != nil) {
						c.JSON(group_mod)
						return
					} else if errgsm != nil {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  errgsm.Message,
						})
						return
					} else {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "Cannot get modified group from LDAP",
						})
						return
					}
				} else {
					// Not found, need to be created
					var base_group ldap.BaseGroup
					body_bytes, err := io.ReadAll(c.Request.Body)
					if (err != nil) || (len(body_bytes) == 0) {
						c.Status(500).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "FATAL: cannot read request body",
						})
						return
					}
					if err := json.Unmarshal(body_bytes, &base_group); err != nil {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "Invalid JSON: cannot be parsed to BaseGroup",
						})
						return
					}
					group_type := base_group.Type
					if !slice.EntryExists(ldap.GROUP_TYPES, group_type) {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "Invalid JSON: invalid group type",
						})
						return
					}
					ldh.CreateGroup(c, body_bytes, group_type, ldap_client)
				}
			}
		}
	case "DELETE":
		var errdel *errors.Error = nil
		if srch_by_mail {
			group_mail, errgm = ldap_client.GroupsMail.GetOne(ldap.MailAttr, gid, "")
			if (errgm == nil) && (group_mail != nil) {
				errdel = ldap_client.GroupsMail.Delete(group_mail.Cn, "")
				if errdel != nil {
					c.JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  errdel.Message,
					})
				} else {
					c.Status(204)
				}
			} else {
				c.JSON(map[string]any{
					"api":    "v1",
					"status": "error",
					"error":  errgm.Message,
				})
			}
		} else {
			var errfin string
			gm, errgm := ldap_client.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
			if (errgm == nil) && (gm != nil) {
				errdel = ldap_client.GroupsMail.Delete(gm.Cn, "")
				if errdel == nil {
					c.Status(204)
				}
			}
			gs, errgs := ldap_client.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
			if (errgs == nil) && (gs != nil) {
				errdel = ldap_client.GroupsMail.Delete(gs.Cn, gs.Ou)
				if errdel == nil {
					c.Status(204)
				}
			}
			if errgm != nil {
				errfin = fmt.Sprintf("Error searching for Mail List Group %s=%s: %s", ldap.CommonNameAttr, gid, errgm.Message)
			}
			if errgs != nil {
				errfin = fmt.Sprintf("%s Error searching for Security Group %s=%s: %s", errfin, ldap.CommonNameAttr, gid, errgs.Message)
			}
			if errdel != nil {
				errfin = fmt.Sprintf("%s Error deleting Group %s=%s: %s", errfin, ldap.CommonNameAttr, gid, errdel.Message)
			}
			if errfin != "" {
				c.JSON(map[string]any{
					"api":    "v1",
					"status": "error",
					"error":  errfin,
				})
			}
		}
	}
}

func (ldh *LdapDataHandler) CreateGroupHandler(c *gofsen.Context) {
	var base_group ldap.BaseGroup
	body_bytes, err := io.ReadAll(c.Request.Body)
	if (err != nil) || (len(body_bytes) == 0) {
		c.Status(500).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "FATAL: cannot read request body",
		})
		return
	}
	if err := json.Unmarshal(body_bytes, &base_group); err != nil {
		c.Status(400).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "Invalid JSON: cannot be parsed to BaseGroup",
		})
		return
	}
	group_type := base_group.Type
	if !slice.EntryExists(ldap.GROUP_TYPES, group_type) {
		c.Status(400).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "Invalid JSON: invalid group type",
		})
		return
	}
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		c.Status(500).JSON(map[string]any{
			"status": "error",
			"error":  "Cannot create LDAP client",
		})
		return
	}
	ldh.CreateGroup(c, body_bytes, group_type, ldap_client)
}

func (ldh *LdapDataHandler) CreateGroup(c *gofsen.Context, body_bytes []byte, group_type string, ldap_client *ldap.Client) {
	switch group_type {
	case ldap.GROUP_TYPES[0]: // "Mail"
		var group ldap.GroupMail
		if err := json.Unmarshal(body_bytes, &group); err != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Invalid JSON: cannot be parsed to GroupMail",
			})
			return
		}
		errc := ldap_client.GroupsMail.CreateGroup(group)
		if errc == nil {
			c.Status(201).JSON(group)
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errc.Message,
			})
		}
	case ldap.GROUP_TYPES[1]: // "Security"
		var group ldap.GroupSec
		if err := json.Unmarshal(body_bytes, &group); err != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Invalid JSON: cannot be parsed to GroupSec",
			})
			return
		}
		errc := ldap_client.GroupsSec.CreateGroup(group)
		if errc == nil {
			c.Status(201).JSON(group)
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errc.Message,
			})
		}
	}
}
