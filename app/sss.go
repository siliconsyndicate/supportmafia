package app

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"supportmafia/server/config"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// SSS defines methods defined in aws sss sdk
type SSS interface {
	AddFileToS3(string, string, int64, []byte) (string, error)
	AddFileToS3WithID(string, string, int64, []byte) (string, error)
}

// SSSImpl implements SSS methods
type SSSImpl struct {
	SSS    *s3.S3
	Config *config.AWSConfig
}

type SSSImplOpts struct {
	Config *config.AWSConfig
}

func NewSSSImpl(opts *SSSImplOpts) SSS {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(opts.Config.Region),
		Credentials: credentials.NewStaticCredentials(
			opts.Config.AccessKeyID,
			opts.Config.SecretAccessKey,
			"",
		),
	})

	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	svc := s3.New(sess)
	awss3 := SSSImpl{SSS: svc, Config: opts.Config}
	return &awss3
}

func (a *SSSImpl) AddFileToS3(fileName, bucket string, fileSize int64, buffer []byte) (string, error) {
	timeStamp := time.Now().String()
	//using regex to eliminate all the special characters from timestamp
	re1, err := regexp.Compile(`[^\w]`)
	if err != nil {
		return "", err
	}
	timeStamp = re1.ReplaceAllString(timeStamp, "")

	//using regex to eliminate all the special characters except period from filename
	re2, err := regexp.Compile(`[^\w.]`)
	if err != nil {
		return "", err
	}
	fileName = re2.ReplaceAllString(timeStamp+fileName, "") //prefixing file name with a stamp

	url := "https://%s.s3.amazonaws.com/%s"
	url = fmt.Sprintf(url, bucket, fileName)
	// Config settings: this is where you choose the bucket, filename, content-type etc.
	// of the file you're uploading.
	_, err = a.SSS.PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(bucket),
		Key:                  aws.String(fileName),
		ACL:                  aws.String("private"),
		Body:                 bytes.NewReader(buffer),
		ContentLength:        aws.Int64(fileSize),
		ContentType:          aws.String(http.DetectContentType(buffer)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
	})
	if err != nil {
		return "", err
	}
	return url, nil
}

func (a *SSSImpl) AddFileToS3WithID(fileName, bucket string, filesize int64, buffer []byte) (string, error) {
	url := "https://%s.s3.amazonaws.com/%s"
	url = fmt.Sprintf(url, bucket, fileName)
	// Config settings: this is where you choose the bucket, filename, content-type etc.
	// of the file you're uploading.
	_, err := a.SSS.PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(bucket),
		Key:                  aws.String(fileName),
		ACL:                  aws.String("private"),
		Body:                 bytes.NewReader(buffer),
		ContentLength:        aws.Int64(filesize),
		ContentType:          aws.String(http.DetectContentType(buffer)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
		ContentEncoding:      aws.String("base64"),
	})
	if err != nil {
		return "", err
	}
	return url, nil
}
