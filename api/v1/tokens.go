package v1

type GetTokenResponse struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	Workspace string `json:"workspace"`
	Scope     string `json:"scope"`
	Expiry    string `json:"expiry"`
	Created   string `json:"created"`
}

type CreateTokenRequest struct {
	Name    string `json:"name"`
	Expires int    `json:"expires"`
}

type CreateTokenResponse struct {
	GetTokenResponse `json:",inline"`
	Token            string `json:"token"`
}
