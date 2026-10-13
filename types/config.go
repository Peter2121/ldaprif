package types

type ConfigApp struct {
	JwtKeyLength       int      `json:"jwt_key_length"`       // bytes, 32 minimum
	JwtAuthValidity    int      `json:"jwt_auth_validity"`    // minutes
	JwtRefreshValidity int      `json:"jwt_refresh_validity"` // minutes
	WebPort            int      `json:"web_port"`
	CorsAllowOrigins   []string `json:"cors_allow_origins"`
	TlsCertFile        string   `json:"tls_cert_file"` // both set: HTTPS, otherwise plain HTTP (reverse proxy expected)
	TlsKeyFile         string   `json:"tls_key_file"`
	AuthMaxFailures    int      `json:"auth_max_failures"`    // failed logins per IP / username before lockout (default 10)
	AuthLockoutMinutes int      `json:"auth_lockout_minutes"` // lockout and counting window (default 15)
}
