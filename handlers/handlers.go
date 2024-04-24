package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	utils "unstoppable-go/util"
)

var (
	ReqStore                      sync.Map
	UnstoppableDomainClientID     = ""
	UnstoppableDomainScope        = "openid wallet messaging:notifications:optional"
	UnstoppableDomainClientSecret = ""
)

func InitUnstoppable(w http.ResponseWriter, r *http.Request) {
	// Create Unstoppable Request Instance
	state := utils.EncodeState(nil)
	log.Println(state)
	nonce, _ := utils.GenerateNonce()
	verifier, challenge, _ := utils.GenerateCodeChallengeAndVerifier(43, "S256")
	ReqStore.Store(state, verifier)
	options := utils.ReqOptions{
		BaseURL: "https://auth.unstoppabledomains.com/oauth2/auth",
		QueryParams: utils.QueryParams{
			CodeChallenge:       challenge,
			Nonce:               nonce,
			State:               state,
			FlowID:              "login",
			ClientID:            UnstoppableDomainClientID,
			ClientSecret:        UnstoppableDomainClientSecret,
			ClientAuthMethod:    "client_secret_basic",
			MaxAge:              "300000",
			Prompt:              "login",
			RedirectURI:         "http://localhost:3000",
			ResponseMode:        "query",
			Scope:               "openid wallet messaging:notifications:optional",
			CodeChallengeMethod: "S256",
			ResponseType:        "code",
			PackageName:         "@uauth/js",
			PackageVersion:      "3.0.1",
		},
		Headers: map[string]string{
			"User-Agent":                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "cross-site",
			"Sec-Fetch-User":            "?1",
		},
	}

	// Parse the base URL
	parsedURL, _ := url.Parse(options.BaseURL)
	/*if err != nil {
		return nil, err
	}*/

	// Set query parameters
	_ = parsedURL.Query()
	params, _ := url.ParseQuery(parsedURL.RawQuery)
	/*if err != nil {
		return nil, err
	}*/
	for key, value := range options.QueryParams.ToMap() {
		params.Set(key, value)
	}
	parsedURL.RawQuery = params.Encode()
	http.Redirect(w, r, parsedURL.String(), http.StatusTemporaryRedirect)
}

func UnstoppableCallBack(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	log.Println(state)
	code_verifier, ok := ReqStore.LoadAndDelete(state)
	log.Println(reflect.TypeOf(code_verifier))
	log.Println(code_verifier)
	if ok {
		token, err := GetRegisterToken(code, code_verifier.(string))
		if err != nil {
			log.Println(err)
		} else {
			responseBody, _ := ParseToken(token.IDToken)
			log.Println(responseBody)
		}
	}
}

func GetRegisterToken(code, codeVerifier string) (*UnstoppableResponse, error) {
	// Define request body
	body := url.Values{}
	body.Set("client_id", UnstoppableDomainClientID)
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("code_verifier", codeVerifier)
	body.Set("redirect_uri", "http://localhost:3000")

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "https://auth.unstoppabledomains.com/oauth2/token", bytes.NewBufferString(body.Encode()))
	if err != nil {
		return nil, err
	}

	// Set Basic Authentication header
	req.SetBasicAuth(UnstoppableDomainClientID, UnstoppableDomainClientSecret)

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response UnstoppableResponse
	err = json.Unmarshal(bodyBytes, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func ParseToken(tokenStr string) (*TokenDetails, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	decodedPayload, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding payload: %v", err)
	}

	var tokenDetails TokenDetails
	if err := json.Unmarshal(decodedPayload, &tokenDetails); err != nil {
		return nil, fmt.Errorf("error unmarshalling payload: %v", err)
	}

	return &tokenDetails, nil
}

type TokenDetails struct {
	Acr              string        `json:"acr"`
	Amr              []string      `json:"amr"`
	AtHash           string        `json:"at_hash"`
	Aud              []string      `json:"aud"`
	AuthTime         int64         `json:"auth_time"`
	DomainLive       bool          `json:"domain_live"`
	Eip4361Message   string        `json:"eip4361_message"`
	Eip4361Signature string        `json:"eip4361_signature"`
	Exp              int64         `json:"exp"`
	Iat              int64         `json:"iat"`
	Iss              string        `json:"iss"`
	Jti              string        `json:"jti"`
	Nonce            string        `json:"nonce"`
	Proof            Proof         `json:"proof"`
	Rat              int64         `json:"rat"`
	Sid              string        `json:"sid"`
	Sub              string        `json:"sub"`
	VerifiedAddress  []interface{} `json:"verified_addresses"`
	WalletAddress    string        `json:"wallet_address"`
	WalletTypeHint   string        `json:"wallet_type_hint"`
}

type Proof struct {
	V1SigEthereum map[string]V1SigEthereum `json:"v1.sig.ethereum"`
}

type V1SigEthereum struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Template  struct {
		Format string            `json:"format"`
		Params map[string]string `json:"params"`
	} `json:"template"`
	Type string `json:"type"`
}

type UnstoppableResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}
