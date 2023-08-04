package app

import (
	"log"
	"os"
	"supportmafia/server/config"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
)

// SES defines methods defined in aws ses sdk
type SES interface {
	SendEmail(*ses.SendEmailInput) (*ses.SendEmailOutput, error)
	SendRawEmail(*ses.SendRawEmailInput) (*ses.SendRawEmailOutput, error)
}

// SESImpl implements SES methods
type SESImpl struct {
	SES    *ses.SES
	Config *config.AWSConfig
}

type SESImplOpts struct {
	Config *config.AWSConfig
}

func NewSESImpl(opts *SESImplOpts) SES {
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

	svc := ses.New(sess)
	awsses := SESImpl{SES: svc, Config: opts.Config}
	return &awsses
}

// SendEmail calls
func (sesi *SESImpl) SendEmail(opts *ses.SendEmailInput) (*ses.SendEmailOutput, error) {
	return sesi.SES.SendEmail(opts)
}

// Send raw email via ses
func (sesi *SESImpl) SendRawEmail(opts *ses.SendRawEmailInput) (*ses.SendRawEmailOutput, error) {
	return sesi.SES.SendRawEmail(opts)
}
