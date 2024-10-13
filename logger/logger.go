package logger

import "github.com/sirupsen/logrus"

type Config struct {
	LogLevel string `mapstructure:"level"`
	DevMode  bool   `mapstructure:"devMode"`
}

type Logger interface {
	Println(...interface{})
	Printf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Fatal(args ...interface{})
	Error(args ...interface{})
}

type appLogger struct {
	Logger

	level   string
	devMode bool
	logger  *logrus.Logger
}

var loggerLevelMap = map[string]logrus.Level{
	"debug": logrus.DebugLevel,
	"info":  logrus.InfoLevel,
	"warn":  logrus.WarnLevel,
	"error": logrus.ErrorLevel,
	"panic": logrus.PanicLevel,
	"fatal": logrus.FatalLevel,
}

func NewAppLogger(cfg *Config) *appLogger {
	return &appLogger{level: cfg.LogLevel, devMode: cfg.DevMode}
}

func (l *appLogger) InitLogger() {
	logLevel := l.level
	level, ok := loggerLevelMap[logLevel]
	if !ok {
		level = logrus.DebugLevel
	}

	logger := logrus.New()
	logger.SetLevel(level)

	if l.devMode {
		logger.SetReportCaller(true)
	}

	l.logger = logger
}

func (l *appLogger) Println(v ...interface{}) {
	l.logger.Println(v...)
}

func (l *appLogger) Printf(format string, v ...interface{}) {
	l.logger.Printf(format, v...)
}

func (l *appLogger) Debugf(format string, v ...interface{}) {
	l.logger.Debugf(format, v...)
}

func (l *appLogger) Infof(format string, v ...interface{}) {
	l.logger.Infof(format, v...)
}

func (l *appLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Fatalf(format, v...)
}

func (l *appLogger) Fatal(args ...interface{}) {
	l.logger.Fatal(args...)
}

func (l *appLogger) Error(args ...interface{}) {
	l.logger.Error(args...)
}
