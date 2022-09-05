package common

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"runtime"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

//getSecret function retrieves the db decret, parses it and return a struct with connection details
func GetSecret(secEnvVarName string) (SecretDetails, error) {
	var secretDetails SecretDetails
	secretName := os.Getenv(secEnvVarName)
	region := os.Getenv("region")
	//Create a Secrets Manager client
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)},
	)
	if err != nil {
		return secretDetails, err
	}
	svc := secretsmanager.New(sess)
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), //VersionStage defaults to AWSCURRENT if unspecified
	}

	//In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
	//See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html

	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				//Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				log.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())

			case secretsmanager.ErrCodeInternalServiceError:
				//An error occurred on the server side.
				log.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())

			case secretsmanager.ErrCodeInvalidParameterException:
				//You provided an invalid value for a parameter.
				log.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())

			case secretsmanager.ErrCodeInvalidRequestException:
				//You provided a parameter value that is not valid for the current state of the resource.
				log.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())

			case secretsmanager.ErrCodeResourceNotFoundException:
				//We can't find the resource that you asked for.
				log.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			}
		} else {
			//Print the error, cast err to awserr.Error to get the Code and
			//Message from an error.
			log.Println(err.Error())
		}
		return secretDetails, err
	}

	//Decrypts secret using the associated KMS CMK.
	//Depending on whether the secret is a string or binary, one of these fields will be populated.
	var secretString, decodedBinarySecret string
	if result.SecretString != nil {
		secretString = *result.SecretString
		json.Unmarshal([]byte(secretString), &secretDetails)
		return secretDetails, nil
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			log.Println("Base64 Decode Error:", err)
			return secretDetails, err
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
	}

	json.Unmarshal([]byte(decodedBinarySecret), &secretDetails)
	return secretDetails, nil
}

type SecretDetails struct {
	Dbname    string `json:"dbname"`
	Port      int    `json:"port"`
	User      string `json:"username"`
	Password  string `json:"password"`
	Host      string `json:"host"`
	DbSslMode string `json:"dbsslmode"`
}

// getCurrentFuncName return the currently executing function name
func GetCurrentFuncName() string {
	pc, _, line, _ := runtime.Caller(1)
	return runtime.FuncForPC(pc).Name() + " line:" + strconv.Itoa(line) + " "
}
