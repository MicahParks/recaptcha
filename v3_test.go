package recaptcha_test

import (
	"context"
	"errors"
	"github.com/MicahParks/recaptcha"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestV3Response_Check(t *testing.T) {
	tests := []struct {
		name      string
		options   recaptcha.V3ResponseCheckOptions
		resp      recaptcha.V3Response
		shouldErr bool
	}{
		{
			name: "Success",
			resp: recaptcha.V3Response{
				Success: true,
			},
		},
		{
			name: "ErrorCodes",
			resp: recaptcha.V3Response{
				ErrorCodes: []string{"ErrorCodes"},
				Success:    true,
			},
			shouldErr: true,
		},
		{
			name: "Wrong Success",
			resp: recaptcha.V3Response{
				Success: false,
			},
			shouldErr: true,
		},
		{
			name: "APKPackageName",
			options: recaptcha.V3ResponseCheckOptions{
				APKPackageName: []string{"APKPackageName"},
			},
			resp: recaptcha.V3Response{
				APKPackageName: "APKPackageName",
				Success:        true,
			},
		},
		{
			name: "Wrong APKPackageName",
			options: recaptcha.V3ResponseCheckOptions{
				APKPackageName: []string{"APKPackageName"},
			},
			resp: recaptcha.V3Response{
				APKPackageName: "WrongAPKPackageName",
				Success:        true,
			},
			shouldErr: true,
		},
		{
			name: "Action",
			options: recaptcha.V3ResponseCheckOptions{
				Action: []string{"Action"},
			},
			resp: recaptcha.V3Response{
				Action:  "Action",
				Success: true,
			},
		},
		{
			name: "Wrong Action",
			options: recaptcha.V3ResponseCheckOptions{
				Action: []string{"Action"},
			},
			resp: recaptcha.V3Response{
				Action:  "WrongAction",
				Success: true,
			},
			shouldErr: true,
		},
		{
			name: "Hostname",
			options: recaptcha.V3ResponseCheckOptions{
				Hostname: []string{"Hostname"},
			},
			resp: recaptcha.V3Response{
				Hostname: "Hostname",
				Success:  true,
			},
		},
		{
			name: "Wrong Hostname",
			options: recaptcha.V3ResponseCheckOptions{
				Hostname: []string{"Hostname"},
			},
			resp: recaptcha.V3Response{
				Hostname: "WrongHostname",
				Success:  true,
			},
			shouldErr: true,
		},
		{
			name: "Score",
			options: recaptcha.V3ResponseCheckOptions{
				Score: 0.5,
			},
			resp: recaptcha.V3Response{
				Score:   0.5,
				Success: true,
			},
		},
		{
			name: "Wrong Score",
			options: recaptcha.V3ResponseCheckOptions{
				Score: 0.5,
			},
			resp: recaptcha.V3Response{
				Score:   0.4,
				Success: true,
			},
			shouldErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.resp.Check(tc.options)
			if err != nil && !errors.Is(err, recaptcha.ErrCheck) {
				t.Fatal("Wrapped error should be recaptcha.ErrCheck.")
			}
			if (err != nil) != tc.shouldErr {
				t.Errorf("Error: %v", err)
			}
		})
	}
}

func TestNewVerifierV3(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"success": true,
			"score": 0.5,
			"action": "Action",
			"challenge_ts": "2020-01-01T00:00:00Z",
			"hostname": "Hostname",
			"error-codes": ["ErrorCodes"],
			"apk_package_name": "APKPackageName"
		}`))
	}))
	defer server.Close()

	options := recaptcha.VerifierV3Options{
		HTTPClient: server.Client(),
		VerifyURL:  server.URL,
	}

	verifier := recaptcha.NewVerifierV3("secret", options)

	resp, err := verifier.Verify(context.Background(), "response", "remoteIP")
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	expected := recaptcha.V3Response{
		APKPackageName: "APKPackageName",
		Action:         "Action",
		ChallengeTS:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		ErrorCodes:     []string{"ErrorCodes"},
		Hostname:       "Hostname",
		Score:          0.5,
		Success:        true,
	}

	if !reflect.DeepEqual(resp, expected) {
		t.Fatalf("The response was not as expected.\n  Expected: %#v\n  Got: %#v", expected, resp)
	}
}

func TestNewTestVerifierV3(t *testing.T) {
	expected := recaptcha.V3Response{
		APKPackageName: "APKPackageName",
		Action:         "Action",
		ChallengeTS:    time.Now(),
		ErrorCodes:     []string{"ErrorCodes"},
		Hostname:       "Hostname",
		Score:          0.5,
		Success:        true,
	}
	verifier := recaptcha.NewTestVerifierV3(expected, nil)
	resp, err := verifier.Verify(context.Background(), "response", "remoteIP")
	if err != nil {
		t.Fatalf("Failed to verify the response: %v", err)
	}
	if !reflect.DeepEqual(resp, expected) {
		t.Fatalf("The response was not as expected.\n  Expected: %#v\n  Got: %#v", expected, resp)
	}
}
