package handlers

import (
	"crypto/rand"
	"net/http/httptest"
	"testing"

	"main/types"

	"github.com/Bakemono-san/gofsen"
	"github.com/atselvan/go-utils/utils/errors"
	"github.com/peter2121/ldap-mcli/ldap"
)

// fakeUsers replaces the LDAP users manager: every lookup returns the configured user.
type fakeUsers struct{ user *ldap.User }

func (f fakeUsers) GetAll() ([]ldap.User, *errors.Error)                  { return nil, nil }
func (f fakeUsers) GetByUid(string) (*ldap.User, *errors.Error)           { return f.user, nil }
func (f fakeUsers) GetByEmail(string) (*ldap.User, *errors.Error)         { return f.user, nil }
func (f fakeUsers) Filter(string, string) ([]ldap.User, *errors.Error)    { return nil, nil }
func (f fakeUsers) FilterByStatus(string) ([]ldap.User, *errors.Error)    { return nil, nil }
func (f fakeUsers) Create(ldap.User) *errors.Error                        { return nil }
func (f fakeUsers) ModifyUser(ldap.User, ldap.User) *errors.Error         { return nil }
func (f fakeUsers) DeleteByUid(string) *errors.Error                      { return nil }
func (f fakeUsers) DeleteByEmail(string) *errors.Error                    { return nil }
func (f fakeUsers) Authenticate() *errors.Error                           { return nil }
func (f fakeUsers) SetNewPassword(string, string) (string, *errors.Error) { return "", nil }

const testHost = "ldaprif.example.test"

func newTestHandler(t *testing.T, admin string) *LdapDataHandler {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	app := &types.ConfigApp{
		JwtKeyLength:       32,
		JwtAuthValidity:    0, // refresh token usable immediately (nbf = now)
		JwtRefreshValidity: 60,
		AuthMaxFailures:    3,
		AuthLockoutMinutes: 15,
	}
	user := &ldap.User{Uid: "admin", Mail: "admin@example.test", DomainAdmin: admin, Status: ldap.UserStatusActive}
	return NewLdapDataHandler(&ldap.ConfigLdap{MailDomain: "example.test"}, &ldap.ConfigMail{}, app, key,
		ldap.UnitTesting(), ldap.WithUsersManager(fakeUsers{user: user}))
}

func newCtx(host string) *gofsen.Context {
	req := httptest.NewRequest("GET", "http://"+host+"/api/v1/users", nil)
	req.Host = host
	return &gofsen.Context{Request: req, ResponseWriter: httptest.NewRecorder()}
}

func signedTokens(t *testing.T, ldh *LdapDataHandler, host, admin string) (string, string) {
	t.Helper()
	auth, refresh, errs := ldh.GetTokens(host, "admin", "example.test", WEB_CLIENT, admin)
	if errs != "" {
		t.Fatal(errs)
	}
	a, err := auth.SignedString(ldh.JwtSignKey)
	if err != nil {
		t.Fatal(err)
	}
	r, err := refresh.SignedString(ldh.JwtSignKey)
	if err != nil {
		t.Fatal(err)
	}
	return a, r
}

func TestAdminAuthTokenAccepted(t *testing.T) {
	ldh := newTestHandler(t, "yes")
	auth, _ := signedTokens(t, ldh, testHost, "yes")
	if !ldh.ValidateAuthToken(newCtx(testHost), auth) {
		t.Fatal("admin auth token rejected")
	}
}

func TestNonAdminAuthTokenRejected(t *testing.T) {
	ldh := newTestHandler(t, "no")
	auth, _ := signedTokens(t, ldh, testHost, "no")
	if ldh.ValidateAuthToken(newCtx(testHost), auth) {
		t.Fatal("non-admin auth token accepted")
	}
}

func TestTokensAreNotInterchangeable(t *testing.T) {
	ldh := newTestHandler(t, "yes")
	auth, refresh := signedTokens(t, ldh, testHost, "yes")
	if ldh.ValidateAuthToken(newCtx(testHost), refresh) {
		t.Fatal("refresh token accepted as auth token")
	}
	if ok, _ := ldh.ValidateReAuthToken(newCtx(testHost), auth); ok {
		t.Fatal("auth token accepted as refresh token")
	}
}

func TestTokenBoundToHost(t *testing.T) {
	ldh := newTestHandler(t, "yes")
	auth, _ := signedTokens(t, ldh, testHost, "yes")
	if ldh.ValidateAuthToken(newCtx("other.example.test"), auth) {
		t.Fatal("token issued for one host accepted on another")
	}
}

func TestRefreshTokenSingleUse(t *testing.T) {
	ldh := newTestHandler(t, "yes")
	_, refresh := signedTokens(t, ldh, testHost, "yes")
	ok, claims := ldh.ValidateReAuthToken(newCtx(testHost), refresh)
	if !ok || claims == nil {
		t.Fatal("valid refresh token rejected")
	}
	ldh.markRefreshUsed(refresh, claims.ExpiresAt.Time)
	if ok, _ := ldh.ValidateReAuthToken(newCtx(testHost), refresh); ok {
		t.Fatal("refresh token replay accepted")
	}
}

func TestRefreshRejectedWhenNoLongerAdmin(t *testing.T) {
	ldh := newTestHandler(t, "no") // LDAP now says the user is not admin
	_, refresh := signedTokens(t, ldh, testHost, "yes")
	if ok, _ := ldh.ValidateReAuthToken(newCtx(testHost), refresh); ok {
		t.Fatal("refresh accepted for a demoted admin")
	}
}

func TestLoginLockout(t *testing.T) {
	ldh := newTestHandler(t, "yes")
	for i := 0; i < 2; i++ {
		ldh.authFailed("ip:10.0.0.1", "user:bob")
	}
	if ldh.authLocked("ip:10.0.0.1", "user:bob") {
		t.Fatal("locked before reaching the threshold")
	}
	ldh.authFailed("ip:10.0.0.1", "user:bob")
	if !ldh.authLocked("ip:10.0.0.1") {
		t.Fatal("IP not locked after max failures")
	}
	if !ldh.authLocked("user:bob") {
		t.Fatal("username not locked after max failures")
	}
	ldh.authSucceeded("ip:10.0.0.1", "user:bob")
	if ldh.authLocked("ip:10.0.0.1", "user:bob") {
		t.Fatal("still locked after a successful login")
	}
}

func TestTokenIdsAreUnique(t *testing.T) {
	ldh := newTestHandler(t, "yes")
	a1, _, _ := ldh.GetTokens(testHost, "admin", "example.test", WEB_CLIENT, "yes")
	a2, _, _ := ldh.GetTokens(testHost, "admin", "example.test", WEB_CLIENT, "yes")
	id1 := a1.Claims.(JwtAuthData).ID
	id2 := a2.Claims.(JwtAuthData).ID
	if id1 == "" || id1 == id2 {
		t.Fatalf("token ids not unique: %q %q", id1, id2)
	}
}
