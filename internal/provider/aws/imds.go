package aws

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// Retrieve instance metadata for AWS EC2 instance
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
	instanceMetadataEndpoint = "http://169.254.169.254/latest/meta-data"

	// IMDSv2 token related constants
	tokenEndpoint      = "http://169.254.169.254/latest/api/token"
	tokenTTLHeader     = "X-aws-ec2-metadata-token-ttl-seconds"
	tokenRequestHeader = "X-aws-ec2-metadata-token"
)

// The VPC identifier
// Automatically retrieved with GetVPCID function.
// For run outside of the cluster, can be set through linker flag, e.g.
// go build -ldflags "-X github.com/quortex/kubestatic/internal/provider/aws.vpcID=$VPC_ID" -a -o manager main.go
var vpcID string

func init() {
	// Get vpc ID from the running instance
	id, err := retrieveVPCID()
	if err != nil {
		panic(err)
	}
	vpcID = id
}

// retrieveVPCID retrieves the VPC ID of the instance.
// It first checks if the VPC ID is already cached. If not, it attempts to get an IMDSv2 token.
// If the token retrieval fails, it falls back to IMDSv1. It then retrieves the MAC address
// and uses it to get the VPC ID.
func retrieveVPCID() (string, error) {
	if vpcID != "" {
		return vpcID, nil
	}

	client := http.Client{Timeout: 3 * time.Second}

	token, err := getV2Token(client)
	if err != nil {
		fmt.Printf("failed getting IMDSv2 token falling back to IMDSv1 : %s", err)
	}

	mac, err := retrieveInstanceMetadata(client, "/mac", token)
	if err != nil {
		return "", err
	}

	body, err := retrieveInstanceMetadata(client, "/network/interfaces/macs/"+mac+"/vpc-id", token)
	if err != nil {
		return "", err
	}

	return body, nil
}

// getV2Token retrieves an IMDSv2 token using the provided HTTP client.
// It sends a PUT request to the token endpoint and returns the token if successful.
func getV2Token(client http.Client) (string, error) {
	req, err := http.NewRequest(http.MethodPut, tokenEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(tokenTTLHeader, "21600")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()

	token, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

// retrieveInstanceMetadata retrieves instance metadata from the specified context path using the provided HTTP client and token.
// It sends a GET request to the instance metadata endpoint and returns the response body if successful.
func retrieveInstanceMetadata(client http.Client, contextPath string, token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, instanceMetadataEndpoint+contextPath, nil)
	if err != nil {
		return "", err
	}

	if token != "" {
		req.Header.Set(tokenRequestHeader, token)
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
