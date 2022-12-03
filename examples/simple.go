package main

import (
	"github.com/MicahParks/recaptcha"
	"log"
	"net/http"
)

func main() {
	verifier := recaptcha.NewVerifierV3("mySecret", recaptcha.VerifierV3Options{})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Limit the HTTP request to 50 Kilobytes.
		//
		// Change this to fit your use case.
		http.MaxBytesReader(w, r.Body, 50000)

		// Parse the HTTP POST form data.
		//
		// The reCAPTCHA token is in HTTP POST form field "g-recaptcha-response" field by default, but if your frontend
		// forms requests differently, you will need to change this.
		err := r.ParseForm()
		if err != nil {
			log.Printf("Failed to parse form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		frontendToken := r.Form.Get("g-recaptcha-response")
		remoteAddr := r.RemoteAddr

		response, err := verifier.Verify(ctx, frontendToken, remoteAddr)
		if err != nil {
			log.Printf("Failed to verify reCAPTCHA: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Printf("reCAPTCHA V3 response: %#v", response)

		// Check the reCAPTCHA response.
		err = response.Check(recaptcha.V3ResponseCheckOptions{
			Action:   []string{"submit"},
			Hostname: []string{"example.com"},
			Score:    0.5,
		})
		if err != nil {
			log.Printf("Failed check for reCAPTCHA response: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
