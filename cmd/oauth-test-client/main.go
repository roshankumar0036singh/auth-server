package main

import (
	"context"
	"log"
	"time"

	// Replace "auth-server" with your actual module name defined in go.mod
	"auth-server/internal/telemetry" 
)

func main() {
	ctx := context.Background()

	// Initialize tracing
	tp, err := telemetry.InitTracer(ctx)
	if err != nil {
		log.Fatalf("failed to initialize tracer: %v", err)
	}
	
	// Flush remaining spans to Jaeger/Zipkin before the application closes
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(shutdownCtx); err != nil {
			log.Printf("error shutting down tracer provider: %v", err)
		}
	}()


	// Callback route - Handle code exchange
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "No code provided", http.StatusBadRequest)
			return
		}

		// Exchange code for token
		tokenURL := fmt.Sprintf("%s/oauth/token", AuthServerURL)
		data := url.Values{}
		data.Set("grant_type", "authorization_code")
		data.Set("code", code)
		data.Set("client_id", ClientID)
		data.Set("client_secret", ClientSecret)
		data.Set("redirect_uri", RedirectURI)

		resp, err := http.PostForm(tokenURL, data)
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var tokenResp struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Error       string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			http.Error(w, "Failed to decode response", http.StatusInternalServerError)
			return
		}

		if tokenResp.Error != "" {
			fmt.Fprintf(w, "Error from auth server: %s", tokenResp.Error)
			return
		}

		// Use token to get user info
		userInfoURL := fmt.Sprintf("%s/oauth/userinfo", AuthServerURL)
		req, _ := http.NewRequest("GET", userInfoURL, nil)
		req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

		client := &http.Client{}
		userResp, err := client.Do(req)
		if err != nil {
			http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
			return
		}
		defer userResp.Body.Close()

		var userMap map[string]interface{}
		json.NewDecoder(userResp.Body).Decode(&userMap)

		// Display success page
		fmt.Fprintf(w, `
			<html>
				<body style="font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 20px;">
					<h1 style="color: #10b981;">Successfully Logged In! 🎉</h1>
					
					<h3>Your Access Token:</h3>
					<pre style="background: #f1f5f9; padding: 10px; overflow-x: auto;">%s</pre>
					
					<h3>Your User Profile:</h3>
					<pre style="background: #f1f5f9; padding: 10px; border-radius: 6px;">%v</pre>
					
					<p><a href="/">Back to Home</a></p>
				</body>
			</html>
		`, tokenResp.AccessToken, userMap)
	})

	log.Printf("Test client running on http://localhost%s", AppPort)
	log.Fatal(http.ListenAndServe(AppPort, nil))
}
