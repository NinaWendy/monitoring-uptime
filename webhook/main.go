package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

// Version info
var (
	Version   = "1.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// UptimeKumaPayload parsed from webhook
type UptimeKumaPayload struct {
	Heartbeat struct {
		MonitorID int       `json:"monitorID"`
		Status    int       `json:"status"`
		Time      string    `json:"time"`
		Msg       string    `json:"msg"`
		Ping      float64   `json:"ping"`
		Important bool      `json:"important"`
		Duration  int       `json:"duration"`
		Down      int       `json:"down"`
		Up        int       `json:"up"`
	} `json:"heartbeat"`
	Monitor struct {
		ID               int      `json:"id"`
		Name             string   `json:"name"`
		URL              string   `json:"url"`
		Hostname         string   `json:"hostname"`
		Port             int      `json:"port"`
		Type             string   `json:"type"`
		Interval         int      `json:"interval"`
		RetryInterval    int      `json:"retryInterval"`
		DNSResolveType   string   `json:"dns_resolve_type"`
		DNSResolveServer string   `json:"dns_resolve_server"`
		Active           bool     `json:"active"`
		Weight           int      `json:"weight"`
		MaxRedirects     int      `json:"maxredirects"`
		PacketSize       int      `json:"packetSize"`
		AcceptedStatuses []string `json:"accepted_statuscodes"`
	} `json:"monitor"`
	Msg string `json:"msg"`
}

type LogEntry struct {
	Timestamp        time.Time `json:"timestamp"`
	MonitorID        int       `json:"monitor_id"`
	MonitorName      string    `json:"monitor_name"`
	MonitorType      string    `json:"monitor_type"`
	TargetHost       string    `json:"target_host"`
	TargetURL        string    `json:"target_url,omitempty"`
	Status           string    `json:"status"`
	Message          string    `json:"message"`
	PingMS           float64   `json:"ping_ms"`
	Duration         int       `json:"duration_seconds"`
	UptimeCount      int       `json:"uptime_count"`
	DowntimeCount    int       `json:"downtime_count"`
	DNSResolveType   string    `json:"dns_resolve_type,omitempty"`
	DNSResolveServer string    `json:"dns_resolve_server,omitempty"`
	Port             int       `json:"port,omitempty"`
	Interval         int       `json:"check_interval_seconds"`
}

type Config struct {
	Port                string
	LogFile             string
	LogDir              string
	MaxLogSize          int64
	BufferSize          int
	FlushInterval       time.Duration
	MaxConcurrentWrites int
	RateLimitPerSecond  int
	RateLimitBurst      int
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	ShutdownTimeout     time.Duration
	MaxRequestBodySize  int64
	EnableMetrics       bool
	MetricsPort         string
}

type Metrics struct {
	RequestsTotal       atomic.Uint64
	RequestsSuccess     atomic.Uint64
	RequestsFailure     atomic.Uint64
	LogsWritten         atomic.Uint64
	LogWriteErrors      atomic.Uint64
	BytesWritten        atomic.Uint64
	BufferDropped       atomic.Uint64
	CurrentBufferSize   atomic.Int64
	RateLimitHits       atomic.Uint64
	AvgProcessingTimeNs atomic.Uint64
}

type BufferedWriter struct {
	file          *os.File
	buffer        chan *LogEntry
	batchSize     int
	flushInterval time.Duration
	wg            sync.WaitGroup
	stopCh        chan struct{}
	metrics       *Metrics
	mu            sync.Mutex
	currentSize   int64
	maxSize       int64
	logFile       string
}

var (
	config         Config
	currentLog     *log.Logger
	metrics        = &Metrics{}
	bufferedWriter *BufferedWriter
	rateLimiter    *rate.Limiter
)

func init() {
	config = Config{
		Port:                getEnv("WEBHOOK_PORT", "8080"),
		LogFile:             getEnv("LOG_FILE", "/srv/uptime-kuma/webhook.log"),
		LogDir:              getEnv("LOG_DIR", "/srv/uptime-kuma"),
		MaxLogSize:          getEnvInt64("MAX_LOG_SIZE", 100*1024*1024), // 100MB
		BufferSize:          getEnvInt("BUFFER_SIZE", 10000),
		FlushInterval:       getEnvDuration("FLUSH_INTERVAL", 1*time.Second),
		MaxConcurrentWrites: getEnvInt("MAX_CONCURRENT_WRITES", runtime.NumCPU()),
		RateLimitPerSecond:  getEnvInt("RATE_LIMIT_PER_SECOND", 10000),
		RateLimitBurst:      getEnvInt("RATE_LIMIT_BURST", 20000),
		ReadTimeout:         getEnvDuration("READ_TIMEOUT", 5*time.Second),
		WriteTimeout:        getEnvDuration("WRITE_TIMEOUT", 10*time.Second),
		IdleTimeout:         getEnvDuration("IDLE_TIMEOUT", 120*time.Second),
		ShutdownTimeout:     getEnvDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		MaxRequestBodySize:  getEnvInt64("MAX_REQUEST_BODY_SIZE", 1*1024*1024),
		EnableMetrics:       getEnvBool("ENABLE_METRICS", true),
		MetricsPort:         getEnv("METRICS_PORT", "9090"),
	}

	if err := os.MkdirAll(config.LogDir, 0755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	currentLog = log.New(os.Stdout, "[WEBHOOK] ", log.LstdFlags|log.Lmicroseconds)
	rateLimiter = rate.NewLimiter(rate.Limit(config.RateLimitPerSecond), config.RateLimitBurst)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		fmt.Sscanf(value, "%d", &result)
		return result
	}
	return defaultValue
}
func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		var result int64
		fmt.Sscanf(value, "%d", &result)
		return result
	}
	return defaultValue
}
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		duration, err := time.ParseDuration(value)
		if err == nil {
			return duration
		}
	}
	return defaultValue
}
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}

// BufferedWriter -- async batch JSON logs
func NewBufferedWriter(logFile string, bufferSize int, flushInterval time.Duration, maxSize int64, m *Metrics) (*BufferedWriter, error) {
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	bw := &BufferedWriter{
		file:          file,
		buffer:        make(chan *LogEntry, bufferSize),
		batchSize:     100,
		flushInterval: flushInterval,
		stopCh:        make(chan struct{}),
		metrics:       m,
		currentSize:   stat.Size(),
		maxSize:       maxSize,
		logFile:       logFile,
	}
	for i := 0; i < config.MaxConcurrentWrites; i++ {
		bw.wg.Add(1)
		go bw.batchWriter()
	}
	return bw, nil
}

func (bw *BufferedWriter) Write(entry *LogEntry) error {
	select {
	case bw.buffer <- entry:
		bw.metrics.CurrentBufferSize.Store(int64(len(bw.buffer)))
		return nil
	default:
		bw.metrics.BufferDropped.Add(1)
		return fmt.Errorf("buffer full, dropped log entry")
	}
}

func (bw *BufferedWriter) batchWriter() {
	defer bw.wg.Done()
	ticker := time.NewTicker(bw.flushInterval)
	defer ticker.Stop()
	batch := make([]*LogEntry, 0, bw.batchSize)
	for {
		select {
		case <-bw.stopCh:
			if len(batch) > 0 {
				bw.flushBatch(batch)
			}
			return
		case entry := <-bw.buffer:
			batch = append(batch, entry)
			if len(batch) >= bw.batchSize {
				bw.flushBatch(batch)
				batch = make([]*LogEntry, 0, bw.batchSize)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				bw.flushBatch(batch)
				batch = make([]*LogEntry, 0, bw.batchSize)
			}
		}
	}
}

func (bw *BufferedWriter) flushBatch(batch []*LogEntry) {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	if bw.currentSize >= bw.maxSize {
		if err := bw.rotate(); err != nil {
			currentLog.Printf("ERROR: Log rotation failed: %v", err)
			bw.metrics.LogWriteErrors.Add(1)
			return
		}
	}
	for _, entry := range batch {
		jsonBytes, err := json.Marshal(entry)
		if err != nil {
			bw.metrics.LogWriteErrors.Add(1)
			continue
		}
		n, err := bw.file.Write(append(jsonBytes, '\n'))
		if err != nil {
			currentLog.Printf("ERROR: Failed to write batch: %v", err)
			bw.metrics.LogWriteErrors.Add(1)
			continue
		}
		bw.currentSize += int64(n)
		bw.metrics.BytesWritten.Add(uint64(n))
		bw.metrics.LogsWritten.Add(1)
	}
}

func (bw *BufferedWriter) rotate() error {
	if err := bw.file.Sync(); err != nil {
		return err
	}
	bw.file.Close()
	timestamp := time.Now().Format("20060102-150405")
	rotatedName := fmt.Sprintf("%s.%s", bw.logFile, timestamp)
	if err := os.Rename(bw.logFile, rotatedName); err != nil {
		return err
	}
	currentLog.Printf("Log rotated to: %s", rotatedName)
	file, err := os.OpenFile(bw.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	bw.file = file
	bw.currentSize = 0
	return nil
}

func (bw *BufferedWriter) Close() error {
	close(bw.stopCh)
	bw.wg.Wait()
	close(bw.buffer)
	remaining := make([]*LogEntry, 0, len(bw.buffer))
	for entry := range bw.buffer {
		remaining = append(remaining, entry)
	}
	if len(remaining) > 0 {
		bw.flushBatch(remaining)
	}
	return bw.file.Close()
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	metrics.RequestsTotal.Add(1)
	if !rateLimiter.Allow() {
		metrics.RateLimitHits.Add(1)
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		metrics.RequestsFailure.Add(1)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		metrics.RequestsFailure.Add(1)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, config.MaxRequestBodySize))
	if err != nil {
		currentLog.Printf("ERROR: Reading body: %v", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		metrics.RequestsFailure.Add(1)
		return
	}
	defer r.Body.Close()
	var payload UptimeKumaPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		currentLog.Printf("ERROR: Parsing JSON: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		metrics.RequestsFailure.Add(1)
		return
	}
	entry := createLogEntry(&payload)
	if err := bufferedWriter.Write(entry); err != nil {
		currentLog.Printf("WARN: %v", err)
	}
	processingTime := time.Since(startTime).Nanoseconds()
	metrics.AvgProcessingTimeNs.Store(uint64(processingTime))
	metrics.RequestsSuccess.Add(1)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func createLogEntry(payload *UptimeKumaPayload) *LogEntry {
	statusStr := getStatusString(payload.Heartbeat.Status)
	targetHost := payload.Monitor.Hostname
	if targetHost == "" && payload.Monitor.URL != "" {
		targetHost = payload.Monitor.URL
	}
	return &LogEntry{
		Timestamp:        time.Now(),
		MonitorID:        payload.Monitor.ID,
		MonitorName:      payload.Monitor.Name,
		MonitorType:      payload.Monitor.Type,
		TargetHost:       targetHost,
		TargetURL:        payload.Monitor.URL,
		Status:           statusStr,
		Message:          payload.Msg,
		PingMS:           payload.Heartbeat.Ping,
		Duration:         payload.Heartbeat.Duration,
		UptimeCount:      payload.Heartbeat.Up,
		DowntimeCount:    payload.Heartbeat.Down,
		DNSResolveType:   payload.Monitor.DNSResolveType,
		DNSResolveServer: payload.Monitor.DNSResolveServer,
		Port:             payload.Monitor.Port,
		Interval:         payload.Heartbeat.Duration,
	}
}

func getStatusString(status int) string {
	switch status {
	case 0:
		return "DOWN"
	case 1:
		return "UP"
	case 2:
		return "PENDING"
	case 3:
		return "MAINTENANCE"
	default:
		return "UNKNOWN"
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "healthy",
		"time":        time.Now().Format(time.RFC3339),
		"version":     Version,
		"buffer_size": len(bufferedWriter.buffer),
		"buffer_cap":  cap(bufferedWriter.buffer),
	})
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "# HELP webhook_requests_total Total webhook requests\n")
	fmt.Fprintf(w, "# TYPE webhook_requests_total counter\n")
	fmt.Fprintf(w, "webhook_requests_total %d\n", metrics.RequestsTotal.Load())
	fmt.Fprintf(w, "webhook_requests_success %d\n", metrics.RequestsSuccess.Load())
	fmt.Fprintf(w, "webhook_requests_failure %d\n", metrics.RequestsFailure.Load())
	fmt.Fprintf(w, "webhook_logs_written %d\n", metrics.LogsWritten.Load())
	fmt.Fprintf(w, "webhook_log_write_errors %d\n", metrics.LogWriteErrors.Load())
	fmt.Fprintf(w, "webhook_bytes_written %d\n", metrics.BytesWritten.Load())
	fmt.Fprintf(w, "webhook_buffer_dropped %d\n", metrics.BufferDropped.Load())
	fmt.Fprintf(w, "webhook_buffer_size %d\n", metrics.CurrentBufferSize.Load())
	fmt.Fprintf(w, "webhook_rate_limit_hits %d\n", metrics.RateLimitHits.Load())
	fmt.Fprintf(w, "webhook_avg_processing_time_ns %d\n", metrics.AvgProcessingTimeNs.Load())
}

func main() {
	currentLog.Printf("Starting Uptime Kuma Webhook Service v%s", Version)
	currentLog.Printf("Build: %s, Commit: %s", BuildTime, GitCommit)
	currentLog.Printf("Port: %s", config.Port)
	currentLog.Printf("Log file: %s", config.LogFile)

	var err error
	bufferedWriter, err = NewBufferedWriter(config.LogFile, config.BufferSize, config.FlushInterval, config.MaxLogSize, metrics)
	if err != nil {
		log.Fatalf("Failed to initialize buffered writer: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	mainMux := http.NewServeMux()
	mainMux.HandleFunc("/webhook", webhookHandler)
	mainMux.HandleFunc("/health", healthHandler)

	mainServer := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      mainMux,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
	}

	var metricsServer *http.Server
	if config.EnableMetrics {
		metricsMux := http.NewServeMux()
		metricsMux.HandleFunc("/metrics", metricsHandler)
		metricsServer = &http.Server{
			Addr:    ":" + config.MetricsPort,
			Handler: metricsMux,
		}
		go func() {
			currentLog.Printf("Metrics server listening on :%s", config.MetricsPort)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				currentLog.Printf("Metrics server error: %v", err)
			}
		}()
	}

	go func() {
		currentLog.Printf("Webhook server listening on :%s", config.Port)
		if err := mainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	<-sigChan
	currentLog.Println("Shutdown signal received...")
	ctx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	defer cancel()
	if err := mainServer.Shutdown(ctx); err != nil {
		currentLog.Printf("Server shutdown error: %v", err)
	}
	if metricsServer != nil {
		if err := metricsServer.Shutdown(ctx); err != nil {
			currentLog.Printf("Metrics server shutdown error: %v", err)
		}
	}
	currentLog.Println("Draining buffer and closing...")
	if err := bufferedWriter.Close(); err != nil {
		currentLog.Printf("Buffer close error: %v", err)
	}
	currentLog.Printf("Shutdown complete. Requests: %d, Success: %d, Dropped: %d",
		metrics.RequestsTotal.Load(), metrics.RequestsSuccess.Load(), metrics.BufferDropped.Load())
}
