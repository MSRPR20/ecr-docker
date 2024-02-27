package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
)

func main() {
	// Specify the AWS region
	region := "ap-southeast-1"

	// Create an AWS session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	if err != nil {
		fmt.Println("Error creating AWS session:", err)
		return
	}

	// Create an ECR client
	ecrClient := ecr.New(sess)

	// Specify the registry ID or URI for your ECR repository
	registryID := "account-id"
	registryURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", registryID, region)

	// Get the authorization token
	authInput := &ecr.GetAuthorizationTokenInput{}
	authOutput, err := ecrClient.GetAuthorizationToken(authInput)
	if err != nil {
		fmt.Println("Error getting authorization token:", err)
		return
	}

	// Extract the token from the authorization data
	token := authOutput.AuthorizationData[0].AuthorizationToken
	decodetoken := string(*token)
	// Decode the base64-encoded token
	decodedToken, err := b64decode(decodetoken)
	if err != nil {
		fmt.Println("Error decoding authorization token:", err)
		return
	}

	// Extract the username and password from the decoded token
	authParts := strings.SplitN(decodedToken, ":", 2)
	username := authParts[0]
	password := authParts[1]
	fmt.Println(password)

	// Perform Docker login using the obtained credentials
	cmd := exec.Command("docker", "login", "--username", username, "--password-stdin", registryURI)
	cmd.Stdin = strings.NewReader(password)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		fmt.Println("Error running docker login:", err)
		return
	}

	fmt.Println("Docker login successful!")

}

func b64decode(encoded string) (string, error) {
	// Implement your base64 decoding logic here
	// You can use encoding/base64 package in the standard library or any other library
	// For example, using encoding/base64:
	decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decodedBytes), nil
}
