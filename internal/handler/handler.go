package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/WICG/webpackage/go/signedexchange/version"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var latestVersion = string(version.AllVersions[len(version.AllVersions)-1])

type ProofRequest struct {
	Data      string `json:"data"`
	SourceUrl string `json:"source_url"`
}
type StatusResponse struct {
	Status     string         `json:"status,omitempty"`
	TrackingId string         `json:"tracking_id,omitempty"`
	Result     *ProofResponse `json:"result,omitempty"`
}

type ProofResponse struct {
	Result          int    `json:"result"`
	VerificationKey string `json:"vkey"`
	PublicKey       string `json:"publicValues"`
	ProofBytes      string `json:"proof"`
}

type ProofInput struct {
	FinalPayload           []byte   `json:"final_payload"`
	DataToVerify           []byte   `json:"data_to_verify"`
	DataToVerifyStartIndex int      `json:"data_to_verify_start_index"`
	IntegrityStartIndex    int      `json:"integrity_start_index"`
	Payload                []byte   `json:"payload"`
	R                      [32]byte `json:"r"`
	S                      [32]byte `json:"s"`
	Px                     [32]byte `json:"px"`
	Py                     [32]byte `json:"py"`
}

func (pi ProofInput) MarshalJSON() ([]byte, error) {
	type Alias ProofInput
	return json.Marshal(&struct {
		FinalPayload           []int    `json:"final_payload"`
		DataToVerify           []int    `json:"data_to_verify"`
		DataToVerifyStartIndex int      `json:"data_to_verify_start_index"`
		IntegrityStartIndex    int      `json:"integrity_start_index"`
		Payload                []int    `json:"payload"`
		R                      [32]byte `json:"r"`
		S                      [32]byte `json:"s"`
		Px                     [32]byte `json:"px"`
		Py                     [32]byte `json:"py"`
		*Alias
	}{
		FinalPayload:           bytesToIntSlice(pi.FinalPayload),
		DataToVerify:           bytesToIntSlice(pi.DataToVerify),
		DataToVerifyStartIndex: pi.DataToVerifyStartIndex,
		IntegrityStartIndex:    pi.IntegrityStartIndex,
		Payload:                bytesToIntSlice(pi.Payload),
		R:                      pi.R,
		S:                      pi.S,
		Px:                     pi.Px,
		Py:                     pi.Py,
	})
}

func bytesToIntSlice(b []byte) []int {
	ints := make([]int, len(b))
	for i, v := range b {
		ints[i] = int(v)
	}
	return ints
}

type HandleProofRequest struct {
	Logger  *zap.Logger
	PrivKey string
}

// func (hp *HandleProofRequest) GetProofStatus(c *gin.Context) {
// 	reqId := strings.ToLower(c.Query("reqId"))
// 	res := StatusResponse{}

// 	// check if reqId-fixture.json exists
// 	filename := fmt.Sprintf("%s-fixture.json", reqId)
// 	if _, err := os.Stat(filename); os.IsNotExist(err) {
// 		if _, err := os.Stat(fmt.Sprintf("%s.json", reqId)); os.IsNotExist(err) {

// 			c.JSON(http.StatusNotFound, gin.H{
// 				"error": "proof request not found",
// 			})
// 			return
// 		} else {
// 			res.Status = "processing"
// 			c.JSON(http.StatusAccepted, res)
// 			return
// 		}
// 	}

// 	// read the file
// 	data, err := os.ReadFile(filename)
// 	if err != nil {
// 		log.Printf("Failed to read file: %v", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{
// 			"error": "internal server error",
// 		})
// 		return
// 	}

// 	proof := ProofResponse{}

// 	if err := json.Unmarshal(data, &proof); err != nil {
// 		log.Printf("Failed to unmarshal JSON: %v", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{
// 			"error": "internal server error",
// 		})
// 		return
// 	}

// 	res.Status = "completed"
// 	res.Result = &proof
// 	c.JSON(http.StatusOK, res)
// }

func (hp *HandleProofRequest) GetProofStatus(c *gin.Context) {
	reqId := strings.ToLower(c.Query("reqId"))
	res := StatusResponse{}

	// Check if reqId-fixture.json exists
	filename := fmt.Sprintf("%s-fixture.json", reqId)
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		if _, err := os.Stat(fmt.Sprintf("%s.json", reqId)); os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "proof request not found",
			})
			return
		} else {
			res.Status = "processing"
			logFileName := fmt.Sprintf("%s.log", reqId)
			if _, err := os.Stat(logFileName); err == nil {
				// Log file exists, let's parse it for the tracking ID
				logContent, err := os.ReadFile(logFileName)
				if err == nil {
					trackingID := extractTrackingID(string(logContent))
					if trackingID != "" {
						res.TrackingId = fmt.Sprintf("https://explorer.succinct.xyz/%s", trackingID)
						c.JSON(http.StatusOK, res)
						return
					}
				}
			}
			c.JSON(http.StatusAccepted, res)
			return
		}
	}

	// Read the fixture file
	data, err := os.ReadFile(filename)
	if err != nil {
		hp.Logger.Error("Failed to read file", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	proof := ProofResponse{}

	if err := json.Unmarshal(data, &proof); err != nil {
		hp.Logger.Error("Failed to unmarshal JSON", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	res.Status = "completed"
	res.Result = &proof
	c.JSON(http.StatusOK, res)
}

func extractTrackingID(logContent string) string {
	lines := strings.Split(logContent, "\n")
	for _, line := range lines {
		if strings.Contains(line, "View in explorer: https://explorer.succinct.xyz/") {
			parts := strings.Split(line, "/")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}
	return ""
}

func (hp *HandleProofRequest) GenerateProofRequest(c *gin.Context) {
	// generate random hex string

	var req ProofRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	reqid := sha256.Sum256([]byte(fmt.Sprintf("%v", req)))
	reqidStr := strings.ToLower(hex.EncodeToString(reqid[:]))

	if err := validateProofRequest(req, reqidStr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	sxg, err := verifySXG(req.SourceUrl, req.Data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	dataStartIndex := findByteArray([]byte(req.Data), sxg.Payload)
	if dataStartIndex <= 0 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Data not found in the payload",
		})
		return
	}

	integrity := []byte{}
	enc := sxg.Version.MiceEncoding()
	if d := sxg.ResponseHeaders.Get("Digest"); d != "" {
		integrity = []byte(d)
	} else {
		var buf bytes.Buffer
		d, err := enc.Encode(&buf, sxg.Payload, 16384)
		if err != nil {
			return
		}
		sxg.Payload = buf.Bytes()
		integrity = []byte(d)
	}

	integrityStartIndex := findByteArray(integrity, sxg.Msg)
	if integrityStartIndex <= 0 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Integrity not found in the signed mes",
		})
		return
	}

	r := [32]byte{}
	copy(r[:], sxg.R.FillBytes(r[:]))

	s := [32]byte{}
	copy(s[:], sxg.S.FillBytes(s[:]))

	px := [32]byte{}
	copy(px[:], sxg.Px.FillBytes(px[:]))

	py := [32]byte{}
	copy(py[:], sxg.Py.FillBytes(py[:]))

	pi := ProofInput{
		FinalPayload:           sxg.Msg,
		DataToVerify:           []byte(req.Data),
		DataToVerifyStartIndex: dataStartIndex,
		IntegrityStartIndex:    integrityStartIndex,
		Payload:                sxg.Payload,
		R:                      r,
		S:                      s,
		Px:                     px,
		Py:                     py,
	}

	// Marshal the ProofInput struct to JSON
	jsonData, err := json.Marshal(pi)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to marshal JSON: %v", err),
		})
		return
	}

	// Write the JSON data to a file
	filename := fmt.Sprintf("%s.json", reqidStr)
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to write file: %v", err),
		})
		return
	}

	// Create a log file for the command output
	logFileName := fmt.Sprintf("%s.log", reqidStr)
	logFile, err := os.Create(logFileName)
	if err != nil {
		hp.Logger.Error("Failed to create log file", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to create log file: %v", err),
		})
		return
	}
	defer logFile.Close()

	// Prepare the CLI command
	cmdArgs := []string{"--system", "groth16", "--input-file-id", reqidStr}
	cmd := exec.Command("/Users/yash/Desktop/crema/sxg-go/cmd/bin/sp1-prover", cmdArgs...)

	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), "SP1_PROVER=network", "SP1_PRIVATE_KEY="+hp.PrivKey, "RUST_LOG=info")

	err = cmd.Start()
	if err != nil {
		hp.Logger.Error("Failed to start Rust program", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to start Rust program: %v", err),
		})
		return
	}

	// Log the process ID for debugging purposes
	hp.Logger.Info("Started Rust program", zap.Int("pid", cmd.Process.Pid))

	c.JSON(http.StatusOK, gin.H{
		"reqId": reqidStr,
	})
}

func verifySXG(sourceUrl string, data string) (*signedexchange.Exchange, error) {
	client := http.DefaultClient
	req, err := http.NewRequest("GET", sourceUrl, nil)
	if err != nil {
		return nil, err
	}
	ver, ok := version.Parse(latestVersion)
	if !ok {
		return nil, fmt.Errorf("failed to parse version %q", latestVersion)
	}
	mimeType := ver.MimeType()
	req.Header.Add("Accept", mimeType)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	respMimeType := resp.Header.Get("Content-Type")
	if respMimeType != mimeType {
		return nil, fmt.Errorf("GET %q responded with unexpected content type %q", sourceUrl, respMimeType)
	}
	var in io.Reader = resp.Body
	defer resp.Body.Close()

	e, err := signedexchange.ReadExchange(in)
	if err != nil {
		return nil, err
	}

	certFetcher := signedexchange.DefaultCertFetcher

	if err := verify(e, certFetcher, time.Now()); err != nil {
		return nil, err
	}

	return e, nil
}

func verify(e *signedexchange.Exchange, certFetcher signedexchange.CertFetcher, verificationTime time.Time) error {
	if decodedPayload, ok := e.Verify(verificationTime, certFetcher, log.New(os.Stdout, "", 0)); ok {
		e.Payload = decodedPayload
		return nil
	}
	return fmt.Errorf("The exchange has an invalid signature.")
}

func findByteArray(a, b []byte) int {
	if len(a) == 0 {
		return 0
	}
	if len(a) > len(b) {
		return -1
	}

	return bytes.Index(b, a)
}

func validateProofRequest(req ProofRequest, reqId string) error {
	if req.Data == "" {
		return fmt.Errorf("data is required")
	}
	if req.SourceUrl == "" {
		return fmt.Errorf("SourceUrl is required")
	}

	// Check if reqId.json exists
	filename := fmt.Sprintf("%s.json", reqId)
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("proof request already exists, try getting status, reqId: %s", reqId)
	}

	return nil
}
