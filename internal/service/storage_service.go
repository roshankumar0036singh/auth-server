package service

import (
	"context"
	"fmt"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type StorageService struct {
	bucket string
	region string
	client *s3.Client
}

func NewStorageService(bucket, region string) *StorageService {
	cfg, err := awsconfig.LoadDefaultConfig(
		context.TODO(),
		awsconfig.WithRegion(region),
	)

	if err != nil {
		panic(err)
	}

	client := s3.NewFromConfig(cfg)

	return &StorageService{
		bucket: bucket,
		region: region,
		client: client,
	}
}

func (s *StorageService) GenerateUploadURL(
	userID string,
	fileName string,
) (string, string, error) {

	objectKey := fmt.Sprintf(
		"users/%s/%s",
		userID,
		fileName,
	)

	presignClient := s3.NewPresignClient(s.client)

	req, err := presignClient.PresignPutObject(
		context.TODO(),
		&s3.PutObjectInput{
			Bucket: &s.bucket,
			Key:    &objectKey,
		},
		func(opts *s3.PresignOptions) {
			opts.Expires = 15 * time.Minute
		},
	)

	if err != nil {
		return "", "", err
	}

	fileURL := fmt.Sprintf(
		"https://%s.s3.%s.amazonaws.com/%s",
		s.bucket,
		s.region,
		objectKey,
	)

	return req.URL, fileURL, nil
}