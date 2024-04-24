package utils

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// ReqOptions contains request parameters and headers
type ReqOptions struct {
	BaseURL     string
	QueryParams QueryParams
	Headers     map[string]string
}

// QueryParams contains query parameters
type QueryParams struct {
	CodeChallenge       string `url:"code_challenge"`
	Nonce               string `url:"nonce"`
	State               string `url:"state"`
	FlowID              string `url:"flow_id"`
	ClientID            string `url:"client_id"`
	ClientSecret        string `url:"client_secret"`
	ClientAuthMethod    string `url:"client_auth_method"`
	MaxAge              string `url:"max_age"`
	Prompt              string `url:"prompt"`
	RedirectURI         string `url:"redirect_uri"`
	ResponseMode        string `url:"response_mode"`
	Scope               string `url:"scope"`
	CodeChallengeMethod string `url:"code_challenge_method"`
	ResponseType        string `url:"response_type"`
	PackageName         string `url:"package_name"`
	PackageVersion      string `url:"package_version"`
}

func makeGETRequestWithParams(options ReqOptions) ([]byte, error) {
	// Parse the base URL
	parsedURL, err := url.Parse(options.BaseURL)
	if err != nil {
		return nil, err
	}

	// Set query parameters
	_ = parsedURL.Query()
	params, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return nil, err
	}
	for key, value := range options.QueryParams.ToMap() {
		params.Set(key, value)
	}
	parsedURL.RawQuery = params.Encode()

	// Create the request
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Set headers
	for key, value := range options.Headers {
		req.Header.Set(key, value)
	}

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// toMap converts QueryParams struct to a map
func (qp QueryParams) ToMap() map[string]string {
	params := make(map[string]string)
	params["code_challenge"] = qp.CodeChallenge
	params["nonce"] = qp.Nonce
	params["state"] = qp.State
	params["flow_id"] = qp.FlowID
	params["client_id"] = qp.ClientID
	params["client_secret"] = qp.ClientSecret
	params["client_auth_method"] = qp.ClientAuthMethod
	params["max_age"] = qp.MaxAge
	params["prompt"] = qp.Prompt
	params["redirect_uri"] = qp.RedirectURI
	params["response_mode"] = qp.ResponseMode
	params["scope"] = qp.Scope
	params["code_challenge_method"] = qp.CodeChallengeMethod
	params["response_type"] = qp.ResponseType
	params["package_name"] = qp.PackageName
	params["package_version"] = qp.PackageVersion
	return params
}


