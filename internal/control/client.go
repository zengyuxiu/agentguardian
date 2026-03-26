package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
}

func NewClient(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
		baseURL: "http://unix",
	}
}

func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/status", nil)
	if err != nil {
		return StatusResponse{}, err
	}

	var resp StatusResponse
	if err := c.do(req, &resp); err != nil {
		return StatusResponse{}, err
	}
	return resp, nil
}

func (c *Client) Validate(ctx context.Context, scope Scope) (ValidateResponse, error) {
	reqURL := c.baseURL + "/v1/validate"
	if scope != "" {
		values := url.Values{}
		values.Set("scope", string(scope))
		reqURL += "?" + values.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return ValidateResponse{}, err
	}

	var resp ValidateResponse
	if err := c.do(req, &resp); err != nil {
		return ValidateResponse{}, err
	}
	return resp, nil
}

func (c *Client) Reload(ctx context.Context) (ReloadResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/reload", nil)
	if err != nil {
		return ReloadResponse{}, err
	}

	var resp ReloadResponse
	if err := c.do(req, &resp); err != nil {
		return ReloadResponse{}, err
	}
	return resp, nil
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if decodeErr := json.NewDecoder(resp.Body).Decode(&errResp); decodeErr == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("request failed with status %s", resp.Status)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}
