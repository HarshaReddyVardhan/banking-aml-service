package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/banking/aml-service/internal/config"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

func main() {
	// 1. Initialize Logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()

	// 2. Load Configuration
	cfg, err := config.Load()
	if err != nil {
		sugar.Fatalf("Failed to load configuration: %v", err)
	}

	// 3. Initialize Echo
	e := echo.New()

	// 4. Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.Secure()) // Security headers

	// CORS Setup
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: cfg.Security.AllowedOrigins,
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
	}))

	// 5. Health Check Route
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	// 6. Start Server (Graceful Shutdown)
	serverAddr := fmt.Sprintf(":%d", cfg.Server.Port)
	
	go func() {
		if err := e.Start(serverAddr); err != nil && err != http.ErrServerClosed {
			sugar.Fatalf("shutting down the server: %v", err)
		}
	}()

	sugar.Infof("Server started on %s", serverAddr)

	// Wait for interrupt signal to gracefully shutdown the server with a timeout
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	sugar.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	
	if err := e.Shutdown(ctx); err != nil {
		sugar.Fatal(err)
	}
	
	sugar.Info("Server exited properly")
}
