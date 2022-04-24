package jwt

import (
	"encoding/base64"
	"encoding/json"
)

func b64JsonEncode(payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func b64JsonDecode(data string, v any) error {
	raw, err := base64.RawStdEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}
