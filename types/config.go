package types

type ConfigApp struct {
	JwtKeyLength       int      `json:"jwt_key_length"`
	JwtAuthValidity    int      `json:"jwt_auth_validity"`
	JwtRefreshValidity int      `json:"jwt_refresh_validity"`
	WebPort            int      `json:"web_port"`
	CorsAllowOrigins   []string `json:"cors_allow_origins"`
}
