package logger

import (
	"aggregator/internal/common/logger"
	"context"
)

type EmptyLogger struct{}

func NewEmptyLogger() *EmptyLogger {
	return &EmptyLogger{}
}

func (l *EmptyLogger) WithFields(fields map[string]interface{}) logger.Logger {
	return &EmptyLogger{}
}

func (l *EmptyLogger) Debug(ctx context.Context, msg string, fields ...interface{}) {}
func (l *EmptyLogger) Info(ctx context.Context, msg string, fields ...interface{})  {}
func (l *EmptyLogger) Warn(ctx context.Context, msg string, fields ...interface{})  {}
func (l *EmptyLogger) Error(ctx context.Context, msg string, fields ...interface{}) {}
func (l *EmptyLogger) Fatal(ctx context.Context, msg string, fields ...interface{}) {}
