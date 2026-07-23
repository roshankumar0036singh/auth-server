package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type StorageService struct {
	bucket string
	region string
	client *s3.Client
}

func NewStorageService(bucket, region string) (*StorageService, error) {
	cfg, err := awsconfig.LoadDefaultConfig(
		context.Background(),
		awsconfig.WithRegion(region),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg)

	return &StorageService{
		bucket: bucket,
		region: region,
		client: client,
	}, nil
}

func (s *StorageService) GenerateUploadURL(
	ctx context.Context,
	userID, fileName string,
) (string, string, error) {

	fileName = strings.TrimSpace(fileName)

	if fileName == "" {
		return "", "", fmt.Errorf("file name is required")
	}

	if strings.Contains(fileName, "/") ||
		strings.Contains(fileName, "\\") ||
		strings.Contains(fileName, "..") {
		return "", "", fmt.Errorf("invalid file name")
	}

	objectKey := fmt.Sprintf(
		"users/%s/%s",
		userID,
		fileName,
	)

	presignClient := s3.NewPresignClient(s.client)

	req, err := presignClient.PresignPutObject(
		ctx,
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