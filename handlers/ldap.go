package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"main/types"

	"github.com/Bakemono-san/gofsen"
	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/go-utils/utils/slice"
	"github.com/golang-jwt/jwt/v5"
	"github.com/peter2121/ldap-mcli/ldap"
)

const MAX_LEN_USERNAME int = 128
const MAX_LEN_PASSWORD int = 128

const EMAIL_VALIDATION_REGEX string = `^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`
const CN_VALIDATION_REGEX string = `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`

const AUTH_ERROR string = "Invalid credentials"
const ADMIN_ERROR string = "Must be domain admin"
const LOCKOUT_ERROR string = "Too many failed login attempts, try again later"
const LDAP_ERROR string = "LDAP operation failed"

const DEFAULT_AUTH_MAX_FAILURES int = 10
const DEFAULT_AUTH_LOCKOUT_MINUTES int = 15

type LdapDataHandler struct {
	LdapConfig *ldap.ConfigLdap
	MailConfig *ldap.ConfigMail
	AppConfig  *types.ConfigApp
	Opts       []ldap.ClientOption
	JwtSignKey []byte

	mu           sync.Mutex
	usedRefresh  map[string]time.Time    // refresh tokens already exchanged (single use) -> their expiry
	authFailures map[string]*authFailure // failed logins per client IP and per username
}

type authFailure struct {
	count       int
	lastFailure time.Time
	lockedUntil time.Time
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

// Validate is called by jwt.ParseWithClaims: an auth token is only valid for a domain admin.
func (m JwtAuthData) Validate() error {
	if !isAdmin(m.IsAdmin) {
		return fmt.Errorf("%s", ADMIN_ERROR)
	}
	return nil
}

const JWT_REFRESH_SUBJECT string = "Refresh"

const WEB_CLIENT string = "web"
const MOBILE_CLIENT string = "mobile"
const DESKTOP_CLIENT string = "desktop"

var CLIENTS = []string{WEB_CLIENT, MOBILE_CLIENT, DESKTOP_CLIENT}

func NewLdapDataHandler(ldap_config *ldap.ConfigLdap, mail_config *ldap.ConfigMail, app_config *types.ConfigApp, jsik []byte, opts ...ldap.ClientOption) *LdapDataHandler {
	ldap_data_handler := LdapDataHandler{}
	ldap_data_handler.LdapConfig = ldap_config
	ldap_data_handler.MailConfig = mail_config
	ldap_data_handler.AppConfig = app_config
	ldap_data_handler.Opts = opts
	ldap_data_handler.JwtSignKey = jsik
	ldap_data_handler.usedRefresh = make(map[string]time.Time)
	ldap_data_handler.authFailures = make(map[string]*authFailure)
	return &ldap_data_handler
}

// Helpers

func isAdmin(flag string) bool {
	return strings.ToUpper(flag) == "YES"
}

// apiError sends a JSON error with the given HTTP status (single response per request).
func apiError(c *gofsen.Context, status int, message string) {
	c.Status(status).JSON(map[string]any{
		"api":    "v1",
		"status": "error",
		"error":  message,
	})
}

// apiLdapError maps a ldap-mcli error to an HTTP response. Internal errors (5xx) are logged and
// replaced by a generic message: LDAP result codes, DNs or hostnames never reach the client.
func apiLdapError(c *gofsen.Context, err *errors.Error) {
	status := err.Status
	if status < 400 || status > 599 {
		status = http.StatusInternalServerError
	}
	message := err.Message
	if status >= 500 {
		log.Printf("LDAP error on %s %s: %s", c.Request.Method, c.Request.URL.Path, err.Message)
		message = LDAP_ERROR
	}
	apiError(c, status, message)
}

// clientIP returns the peer address. X-Forwarded-For is deliberately ignored: it is client-controlled
// unless a trusted reverse proxy is configured.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Login throttling

func (ldh *LdapDataHandler) authLimits() (int, time.Duration) {
	max_failures := ldh.AppConfig.AuthMaxFailures
	if max_failures <= 0 {
		max_failures = DEFAULT_AUTH_MAX_FAILURES
	}
	lockout_minutes := ldh.AppConfig.AuthLockoutMinutes
	if lockout_minutes <= 0 {
		lockout_minutes = DEFAULT_AUTH_LOCKOUT_MINUTES
	}
	return max_failures, time.Duration(lockout_minutes) * time.Minute
}

// authLocked reports whether one of the keys (client IP, username) is currently locked out.
func (ldh *LdapDataHandler) authLocked(keys ...string) bool {
	ldh.mu.Lock()
	defer ldh.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		if f, ok := ldh.authFailures[k]; ok && now.Before(f.lockedUntil) {
			return true
		}
	}
	return false
}

// authFailed records a failed login; AuthMaxFailures within the lockout window locks the key.
func (ldh *LdapDataHandler) authFailed(keys ...string) {
	max_failures, window := ldh.authLimits()
	ldh.mu.Lock()
	defer ldh.mu.Unlock()
	now := time.Now()
	if len(ldh.authFailures) > 10000 { // bound memory: drop stale entries
		for k, f := range ldh.authFailures {
			if now.Sub(f.lastFailure) > window && now.After(f.lockedUntil) {
				delete(ldh.authFailures, k)
			}
		}
	}
	for _, k := range keys {
		f := ldh.authFailures[k]
		if f == nil || now.Sub(f.lastFailure) > window {
			f = &authFailure{}
			ldh.authFailures[k] = f
		}
		f.count++
		f.lastFailure = now
		if f.count >= max_failures {
			f.lockedUntil = now.Add(window)
		}
	}
}

func (ldh *LdapDataHandler) authSucceeded(keys ...string) {
	ldh.mu.Lock()
	defer ldh.mu.Unlock()
	for _, k := range keys {
		delete(ldh.authFailures, k)
	}
}

// Refresh tokens are single use

func (ldh *LdapDataHandler) refreshUsed(token string) bool {
	ldh.mu.Lock()
	defer ldh.mu.Unlock()
	_, used := ldh.usedRefresh[token]
	return used
}

func (ldh *LdapDataHandler) markRefreshUsed(token string, expiry time.Time) {
	ldh.mu.Lock()
	defer ldh.mu.Unlock()
	now := time.Now()
	for t, exp := range ldh.usedRefresh { // expired tokens are rejected by the parser anyway
		if now.After(exp) {
			delete(ldh.usedRefresh, t)
		}
	}
	ldh.usedRefresh[token] = expiry
}

// Handlers

func (ldh *LdapDataHandler) AuthHandler(c *gofsen.Context) {
	type AuthData struct {
		UserName string `json:"username"`
		Password string `json:"password"`
		Client   string `json:"client"`
	}
	var auth_data = AuthData{}
	if err := c.BindJSON(&auth_data); err != nil {
		apiError(c, http.StatusBadRequest, "Invalid JSON")
		return
	}
	if (len(auth_data.UserName) > MAX_LEN_USERNAME) || (len(auth_data.Password) > MAX_LEN_PASSWORD) || (len(auth_data.Password) == 0) {
		apiError(c, http.StatusUnauthorized, AUTH_ERROR)
		return
	}
	if !slice.EntryExists(CLIENTS, auth_data.Client) {
		apiError(c, http.StatusBadRequest, "Invalid client")
		return
	}

	email_regex := regexp.MustCompile(EMAIL_VALIDATION_REGEX)
	cn_regex := regexp.MustCompile(CN_VALIDATION_REGEX)

	if strings.Contains(auth_data.UserName, "@") {
		if !email_regex.MatchString(auth_data.UserName) {
			apiError(c, http.StatusUnauthorized, AUTH_ERROR)
			return
		}
	} else {
		if !cn_regex.MatchString(auth_data.UserName) {
			apiError(c, http.StatusUnauthorized, AUTH_ERROR)
			return
		}
	}

	ip_key := "ip:" + clientIP(c.Request)
	user_key := "user:" + strings.ToLower(auth_data.UserName)
	if ldh.authLocked(ip_key, user_key) {
		apiError(c, http.StatusTooManyRequests, LOCKOUT_ERROR)
		return
	}

	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		apiError(c, http.StatusInternalServerError, "Cannot create LDAP client")
		return
	}
	user, errauth := ldap_client.AuthenticateUser(auth_data.UserName, auth_data.Password)
	if errauth != nil || user == nil {
		ldh.authFailed(ip_key, user_key)
		apiError(c, http.StatusUnauthorized, AUTH_ERROR)
		return
	}
	ldh.authSucceeded(ip_key, user_key)

	// Tokens are only issued to domain admins: a non-admin token would be rejected on every call
	if !isAdmin(user.DomainAdmin) {
		apiError(c, http.StatusForbidden, ADMIN_ERROR)
		return
	}
	ldh.issueTokens(c, auth_data.UserName, auth_data.Client, user.DomainAdmin)
}

func (ldh *LdapDataHandler) ReAuthHandler(c *gofsen.Context) {
	type ReAuthData struct {
		RefreshToken string `json:"refresh_token"`
		Client       string `json:"client"`
	}
	var reauth_data = ReAuthData{}
	if err := c.BindJSON(&reauth_data); err != nil {
		apiError(c, http.StatusBadRequest, "Invalid JSON")
		return
	}

	refresh_token_string := reauth_data.RefreshToken
	if len(refresh_token_string) == 0 {
		apiError(c, http.StatusBadRequest, "Cannot get reauthentication token from data sent")
		return
	}

	ok, claims := ldh.ValidateReAuthToken(c, refresh_token_string)
	if (!ok) || (claims == nil) {
		apiError(c, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	// Single use: a stolen refresh token cannot be replayed once the legitimate client used it
	expiry := time.Now()
	if claims.ExpiresAt != nil {
		expiry = claims.ExpiresAt.Time
	}
	ldh.markRefreshUsed(refresh_token_string, expiry)

	ldh.issueTokens(c, claims.Audience[1], claims.Audience[0], claims.IsAdmin)
}

// issueTokens signs and returns a new auth/refresh token pair.
func (ldh *LdapDataHandler) issueTokens(c *gofsen.Context, username, client, isadmin string) {
	auth_token, refresh_token, strerrtok := ldh.GetTokens(c.Request.Host, username, ldh.LdapConfig.MailDomain, client, isadmin)
	if len(strerrtok) > 0 {
		log.Printf("Cannot build tokens for %s: %s", username, strerrtok)
		apiError(c, http.StatusInternalServerError, "Cannot get authentication tokens")
		return
	}
	if (auth_token == nil) || (refresh_token == nil) {
		apiError(c, http.StatusInternalServerError, "Cannot get authentication tokens")
		return
	}

	auth_token_signed, errsigna := auth_token.SignedString(ldh.JwtSignKey)
	if errsigna != nil {
		log.Printf("Cannot sign auth token: %v", errsigna)
		apiError(c, http.StatusInternalServerError, "Cannot sign authentication tokens")
		return
	}
	refresh_token_signed, errsignr := refresh_token.SignedString(ldh.JwtSignKey)
	if errsignr != nil {
		log.Printf("Cannot sign refresh token: %v", errsignr)
		apiError(c, http.StatusInternalServerError, "Cannot sign authentication tokens")
		return
	}

	c.JSON(JwtResponse{
		JwtAuthToken:    auth_token_signed,
		JwtRefreshToken: refresh_token_signed,
	})
}

func (ldh *LdapDataHandler) ValidateReAuthToken(c *gofsen.Context, reauth_token_string string) (bool, *JwtAuthData) {
	if ldh.refreshUsed(reauth_token_string) {
		log.Printf("Refresh token replay rejected")
		return false, nil
	}
	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		reauth_token_string,
		&claims,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return ldh.JwtSignKey, nil
		},
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithLeeway(1*time.Minute),
		jwt.WithAudience(CLIENTS...),
		jwt.WithIssuer(c.Request.Host),
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

	// The admin status is re-read from LDAP: a demoted admin cannot keep refreshing
	if strings.Contains(username, "@") {
		user, erru = ldap_client.Users.GetByEmail(username)
	} else {
		user, erru = ldap_client.Users.GetByUid(username)
	}

	if erru != nil || user == nil {
		log.Printf("Cannot find user %s in LDAP: %v", username, erru)
		return false, nil
	}

	if !isAdmin(user.DomainAdmin) {
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
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return ldh.JwtSignKey, nil
		},
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithLeeway(1*time.Minute),
		jwt.WithAudience(CLIENTS...),
		jwt.WithIssuer(c.Request.Host),
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

	// Explicit on top of JwtAuthData.Validate(): the API is admin-only
	if !isAdmin(claims.IsAdmin) {
		log.Printf("Token is not an admin token")
		return false
	}
	return true
}

func (ldh *LdapDataHandler) GetTokens(hostname, username, maildomain, client, isadmin string) (*jwt.Token, *jwt.Token, string) {
	id, errid := randomID()
	if errid != nil {
		return nil, nil, "Cannot generate token id"
	}
	timestamp_iss := time.Now()
	timestamp_exp_auth := timestamp_iss.Add(time.Duration(time.Minute * time.Duration(ldh.AppConfig.JwtAuthValidity)))
	timestamp_exp_refresh := timestamp_iss.Add(time.Duration(time.Minute * time.Duration(ldh.AppConfig.JwtRefreshValidity)))
	timestamp_nbf_refresh := timestamp_iss.Add(time.Duration(time.Minute * time.Duration(ldh.AppConfig.JwtAuthValidity/2)))

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
		apiError(c, http.StatusInternalServerError, "Cannot create LDAP client")
		return
	}
	users, err := ldap_client.Users.GetAll()
	if err != nil {
		apiLdapError(c, err)
		return
	}
	c.JSON(users)
}

func (ldh *LdapDataHandler) UserHandler(c *gofsen.Context) {
	var user, user_old *ldap.User = nil, nil
	var err *errors.Error
	uid := c.Param("uid")
	srch_by_mail := strings.Contains(uid, "@")
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		apiError(c, http.StatusInternalServerError, "Cannot create LDAP client")
		return
	}
	switch c.Request.Method {
	case "GET":
		if srch_by_mail {
			user, err = ldap_client.Users.GetByEmail(uid)
		} else {
			user, err = ldap_client.Users.GetByUid(uid)
		}
		if err != nil {
			apiLdapError(c, err)
			return
		}
		if user == nil {
			apiError(c, http.StatusNotFound, "User not found")
			return
		}
		c.JSON(user)
	case "PUT":
		if srch_by_mail {
			user_old, err = ldap_client.Users.GetByEmail(uid)
		} else {
			user_old, err = ldap_client.Users.GetByUid(uid)
		}
		if err != nil {
			apiLdapError(c, err)
			return
		}
		if user_old == nil {
			apiError(c, http.StatusNotFound, "Cannot find existing user to modify")
			return
		}
		var user_new ldap.User
		if err := c.BindJSON(&user_new); err != nil {
			apiError(c, http.StatusBadRequest, "Invalid JSON")
			return
		}
		// mail is immutable and identifies the entry to modify: the body cannot retarget another user
		if user_new.Mail == "" {
			user_new.Mail = user_old.Mail
		} else if user_new.Mail != user_old.Mail {
			apiError(c, http.StatusBadRequest, "mail cannot be changed")
			return
		}
		errmod := ldap_client.Users.ModifyUser(user_new, *user_old)
		if errmod != nil {
			apiLdapError(c, errmod)
			return
		}
		user_mod, errum := ldap_client.Users.GetByEmail(user_old.Mail)
		if errum != nil {
			apiLdapError(c, errum)
			return
		}
		if user_mod == nil {
			apiError(c, http.StatusInternalServerError, "Cannot get modified user from LDAP")
			return
		}
		c.JSON(user_mod)
	case "DELETE":
		if srch_by_mail {
			err = ldap_client.Users.DeleteByEmail(uid)
		} else {
			err = ldap_client.Users.DeleteByUid(uid)
		}
		if err != nil {
			apiLdapError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func (ldh *LdapDataHandler) CreateUserHandler(c *gofsen.Context) {
	var user ldap.User
	if err := c.BindJSON(&user); err != nil {
		apiError(c, http.StatusBadRequest, "Invalid JSON")
		return
	}
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		apiError(c, http.StatusInternalServerError, "Cannot create LDAP client")
		return
	}
	errc := ldap_client.Users.Create(user)
	if errc != nil {
		apiLdapError(c, errc)
		return
	}
	user.UserPassword = "" // never echo the password back
	c.Status(http.StatusCreated).JSON(user)
}

func (ldh *LdapDataHandler) GroupsHandler(c *gofsen.Context) {
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		apiError(c, http.StatusInternalServerError, "Cannot create LDAP client")
		return
	}
	// A missing group subtree (404) is an empty list, any other failure is an error
	groupss, errgs := ldap_client.GroupsSec.GetAll()
	if errgs != nil && errgs.Status != http.StatusNotFound {
		apiLdapError(c, errgs)
		return
	}
	groupsm, errgm := ldap_client.GroupsMail.GetAll()
	if errgm != nil && errgm.Status != http.StatusNotFound {
		apiLdapError(c, errgm)
		return
	}
	result := make([]any, 0, len(groupss)+len(groupsm))
	for _, g := range groupss {
		result = append(result, g)
	}
	for _, g := range groupsm {
		result = append(result, g)
	}
	c.JSON(result)
}

func (ldh *LdapDataHandler) GroupHandler(c *gofsen.Context) {
	gid := c.Param("gid")
	srch_by_mail := strings.Contains(gid, "@")

	var group_mail *ldap.GroupMail = nil
	var errgm *errors.Error = nil
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		apiError(c, http.StatusInternalServerError, "Cannot create LDAP client")
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
		if errgm != nil {
			apiLdapError(c, errgm)
			return
		}
		if group_mail == nil {
			apiError(c, http.StatusNotFound, "Group not found")
			return
		}
		c.JSON(group_mail)
	case "PUT":
		var group_sec *ldap.GroupSec = nil
		if srch_by_mail {
			apiError(c, http.StatusBadRequest, "Groups are modified by cn, not by mail")
			return
		}
		group_old, errgs := ldap_client.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
		if (errgs == nil) && (group_old != nil) {
			if err := c.BindJSON(&group_sec); err != nil || group_sec == nil {
				apiError(c, http.StatusBadRequest, "Invalid JSON")
				return
			}
			errmod := ldap_client.GroupsSec.ModifyGroup(*group_sec, *group_old)
			if errmod != nil {
				apiLdapError(c, errmod)
				return
			}
			group_mod, errgsm := ldap_client.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
			if errgsm != nil {
				apiLdapError(c, errgsm)
				return
			}
			if group_mod == nil {
				apiError(c, http.StatusInternalServerError, "Cannot get modified group from LDAP")
				return
			}
			c.JSON(group_mod)
			return
		}
		group_mail_old, errgmo := ldap_client.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
		if (errgmo == nil) && (group_mail_old != nil) {
			if err := c.BindJSON(&group_mail); err != nil || group_mail == nil {
				apiError(c, http.StatusBadRequest, "Invalid JSON")
				return
			}
			errmod := ldap_client.GroupsMail.ModifyGroup(*group_mail, *group_mail_old)
			if errmod != nil {
				apiLdapError(c, errmod)
				return
			}
			group_mod, errgsm := ldap_client.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
			if errgsm != nil {
				apiLdapError(c, errgsm)
				return
			}
			if group_mod == nil {
				apiError(c, http.StatusInternalServerError, "Cannot get modified group from LDAP")
				return
			}
			c.JSON(group_mod)
			return
		}
		// Not found, need to be created
		body_bytes, group_type, ok := ldh.readGroupBody(c)
		if !ok {
			return
		}
		ldh.CreateGroup(c, body_bytes, group_type, ldap_client)
	case "DELETE":
		if srch_by_mail {
			group_mail, errgm = ldap_client.GroupsMail.GetOne(ldap.MailAttr, gid, "")
			if errgm != nil {
				apiLdapError(c, errgm)
				return
			}
			if group_mail == nil {
				apiError(c, http.StatusNotFound, "Group not found")
				return
			}
			if errdel := ldap_client.GroupsMail.Delete(group_mail.Cn, ""); errdel != nil {
				apiLdapError(c, errdel)
				return
			}
			c.Status(http.StatusNoContent)
			return
		}
		// By cn: both the mail list and the security group with that cn are deleted
		deleted := 0
		gm, errgm := ldap_client.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
		if (errgm == nil) && (gm != nil) {
			if errdel := ldap_client.GroupsMail.Delete(gm.Cn, ""); errdel != nil {
				apiLdapError(c, errdel)
				return
			}
			deleted++
		} else if errgm != nil && errgm.Status != http.StatusNotFound {
			apiLdapError(c, errgm)
			return
		}
		gs, errgs := ldap_client.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
		if (errgs == nil) && (gs != nil) {
			if errdel := ldap_client.GroupsSec.Delete(gs.Cn, gs.Ou); errdel != nil {
				apiLdapError(c, errdel)
				return
			}
			deleted++
		} else if errgs != nil && errgs.Status != http.StatusNotFound {
			apiLdapError(c, errgs)
			return
		}
		if deleted == 0 {
			apiError(c, http.StatusNotFound, "Group not found")
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// readGroupBody reads the request body and extracts a valid group type from it.
func (ldh *LdapDataHandler) readGroupBody(c *gofsen.Context) ([]byte, string, bool) {
	var base_group ldap.BaseGroup
	body_bytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		apiError(c, http.StatusBadRequest, "Cannot read request body")
		return nil, "", false
	}
	if len(body_bytes) == 0 {
		apiError(c, http.StatusBadRequest, "Empty request body")
		return nil, "", false
	}
	if err := json.Unmarshal(body_bytes, &base_group); err != nil {
		apiError(c, http.StatusBadRequest, "Invalid JSON: cannot be parsed to BaseGroup")
		return nil, "", false
	}
	if !slice.EntryExists(ldap.GROUP_TYPES, base_group.Type) {
		apiError(c, http.StatusBadRequest, "Invalid JSON: invalid group type")
		return nil, "", false
	}
	return body_bytes, base_group.Type, true
}

func (ldh *LdapDataHandler) CreateGroupHandler(c *gofsen.Context) {
	body_bytes, group_type, ok := ldh.readGroupBody(c)
	if !ok {
		return
	}
	ldap_client := ldap.NewClient(ldh.LdapConfig, ldh.MailConfig, ldh.Opts...)
	if ldap_client == nil {
		apiError(c, http.StatusInternalServerError, "Cannot create LDAP client")
		return
	}
	ldh.CreateGroup(c, body_bytes, group_type, ldap_client)
}

func (ldh *LdapDataHandler) CreateGroup(c *gofsen.Context, body_bytes []byte, group_type string, ldap_client *ldap.Client) {
	switch group_type {
	case ldap.GROUP_TYPES[0]: // "Mail"
		var group ldap.GroupMail
		if err := json.Unmarshal(body_bytes, &group); err != nil {
			apiError(c, http.StatusBadRequest, "Invalid JSON: cannot be parsed to GroupMail")
			return
		}
		if errc := ldap_client.GroupsMail.CreateGroup(group); errc != nil {
			apiLdapError(c, errc)
			return
		}
		c.Status(http.StatusCreated).JSON(group)
	case ldap.GROUP_TYPES[1]: // "Security"
		var group ldap.GroupSec
		if err := json.Unmarshal(body_bytes, &group); err != nil {
			apiError(c, http.StatusBadRequest, "Invalid JSON: cannot be parsed to GroupSec")
			return
		}
		if errc := ldap_client.GroupsSec.CreateGroup(group); errc != nil {
			apiLdapError(c, errc)
			return
		}
		c.Status(http.StatusCreated).JSON(group)
	}
}
