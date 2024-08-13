package auth

import "errors"

var ErrInvalidToken = errors.New("tokens: invalid token")

type tokenClient struct {
	// This struct is not implemented yet
}

func (t tokenClient) exchangeTokenForBearer(token string) (string, error) {
	// This function is not implemented yet
	return token, nil
}
