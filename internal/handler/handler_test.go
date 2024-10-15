package handler_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crema-labs/sxg-go/internal/handler"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandlePost(t *testing.T) {
	// Set Gin to Test Mode
	gin.SetMode(gin.TestMode)

	// Test cases
	tests := []struct {
		name           string
		inputJSON      string
		expectedStatus int
		expectedBody   string
	}{
		// {
		// 	name:           "Valid input",
		// 	inputJSON:      `{}`, // TODO: Fill in with valid input
		// 	expectedStatus: http.StatusOK,
		// 	expectedBody:   `{"message":"POST request received"}`,
		// },
		{
			name:           "Invalid input - empty data",
			inputJSON:      `{"source_url":"https://blog.crema.sh","data":"Building foundational libraries to remove limitations for the future projects and "}`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"Data is required"}`,
		},
		// {
		// 	name:           "Invalid input - empty source_url",
		// 	inputJSON:      `{"data":"some data"}`,
		// 	expectedStatus: http.StatusBadRequest,
		// 	expectedBody:   `{"error":"SourceUrl is required"}`,
		// },
		// TODO: Add more test cases as needed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a response recorder
			w := httptest.NewRecorder()

			// Create a request
			req, _ := http.NewRequest("POST", "/", bytes.NewBufferString(tt.inputJSON))
			req.Header.Set("Content-Type", "application/json")

			// Create a Gin router with the handler
			hpr := handler.HandleProofRequest{
				PrivKey: "",
			}
			r := gin.New()
			r.POST("/", hpr.HandlePost)

			// Serve the request
			r.ServeHTTP(w, req)

			// Assert the status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Assert the response body
			assert.JSONEq(t, tt.expectedBody, w.Body.String())
		})
	}
}
