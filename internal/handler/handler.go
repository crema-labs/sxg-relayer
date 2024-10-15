package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/WICG/webpackage/go/signedexchange/version"
	"github.com/gin-gonic/gin"
)

var latestVersion = string(version.AllVersions[len(version.AllVersions)-1])

type ProofRequest struct {
	Data      string `json:"data"`
	SourceUrl string `json:"source_url"`
}

type ProofResponse struct {
	Proof string `json:"proof"`
}

// pub struct SXGInput {
// 	pub final_payload: Vec<u8>,
// 	pub data_to_verify: Vec<u8>,
// 	pub data_to_verify_start_index: usize,
// 	pub integrity_start_index: usize,
// 	pub payload: Vec<u8>,
// 	pub r: [u8; 32],
// 	pub s: [u8; 32],
// 	pub px: [u8; 32],
// 	pub py: [u8; 32],
//     }

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
	PrivKey string
}

func (hp *HandleProofRequest) HandlePost(c *gin.Context) {
	// generate random hex string

	var req ProofRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	reqid := sha256.Sum256([]byte(fmt.Sprintf("%v", req)))

	if err := validateProofRequest(req); err != nil {
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
	filename := fmt.Sprintf("%x.json", reqid)
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to write file: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"reqId": fmt.Sprintf("%x", reqid),
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
		fmt.Println("The exchange has a valid signature.")
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

func validateProofRequest(req ProofRequest) error {
	if req.Data == "" {
		return fmt.Errorf("data is required")
	}
	if req.SourceUrl == "" {
		return fmt.Errorf("SourceUrl is required")
	}
	return nil
}
