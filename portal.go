package grpcportal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/soheilhy/cmux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server is the portal which contains the gRPC and HTTP server
type Server struct {
	httpServer *http.Server
	grpcServer *grpc.Server
	isSecure   bool
}

// Serve starts the server on the configured hostname and port
func (s *Server) Serve() error {
	// Create a new listener
	lis, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on specified address (%s)", s.httpServer.Addr)
	}

	// If the server is secure then call serve using the TLS config
	if s.isSecure {
		return s.httpServer.Serve(tls.NewListener(lis, s.httpServer.TLSConfig))
	}

	// If the server is insecure we use cmux to serve
	m := cmux.New(lis)
	go s.grpcServer.Serve(m.Match(cmux.HTTP2()))
	go s.httpServer.Serve(m.Match(cmux.HTTP1()))
	return m.Serve()
}

// GRPCServer interface specifies the methods for registering a gRPC server
type GRPCServer interface {
	RegisterServer(srv *grpc.Server)
	RegisterHandlersFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error
}

// SecureConfig is the server configuration for a secure server
type SecureConfig struct {
	Hostname     string
	Port         int
	Cert         []byte
	Key          []byte
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Addr provides the listener address made of from Hostname and Port
func (cfg SecureConfig) Addr() string {
	return fmt.Sprintf("%s:%d", cfg.Hostname, cfg.Port)
}

// GetReadTimeout provides the configured read timeout or a default
func (cfg SecureConfig) GetReadTimeout() time.Duration {
	if cfg.ReadTimeout > 0 {
		return cfg.ReadTimeout
	}
	return time.Duration(30) * time.Second
}

// GetWriteTimeout provides the configured read timeout or a default
func (cfg SecureConfig) GetWriteTimeout() time.Duration {
	if cfg.WriteTimeout > 0 {
		return cfg.WriteTimeout
	}
	return time.Duration(30) * time.Second
}

// InsecureConfig is the server configuration for an insecure server
type InsecureConfig struct {
	Hostname     string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Addr provides the listener address made of from Hostname and Port
func (cfg InsecureConfig) Addr() string {
	return fmt.Sprintf("%s:%d", cfg.Hostname, cfg.Port)
}

// GetReadTimeout provides the configured read timeout or a default
func (cfg InsecureConfig) GetReadTimeout() time.Duration {
	if cfg.ReadTimeout > 0 {
		return cfg.ReadTimeout
	}
	return time.Duration(30) * time.Second
}

// GetWriteTimeout provides the configured read timeout or a default
func (cfg InsecureConfig) GetWriteTimeout() time.Duration {
	if cfg.WriteTimeout > 0 {
		return cfg.WriteTimeout
	}
	return time.Duration(30) * time.Second
}

// NewSecure returns a new secure server
func NewSecure(g GRPCServer, cfg SecureConfig) (*Server, error) {

	keyPair, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(cfg.Cert)
	if !ok {
		return nil, fmt.Errorf("bad certificates")
	}

	grpcSrv := grpc.NewServer([]grpc.ServerOption{grpc.Creds(credentials.NewClientTLSFromCert(certPool, cfg.Addr()))}...)
	g.RegisterServer(grpcSrv)

	dialOptions := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		ServerName: cfg.Hostname,
		RootCAs:    certPool,
	}))}

	gwmux := runtime.NewServeMux()
	err = g.RegisterHandlersFromEndpoint(context.Background(), gwmux, cfg.Addr(), dialOptions)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	//mux.Handle("/swagger/", http.StripPrefix("/swagger/", serveJSON(http.Dir("./"))))
	mux.Handle("/", gwmux)

	return &Server{
		httpServer: &http.Server{
			Addr:         cfg.Addr(),
			ReadTimeout:  cfg.GetReadTimeout(),
			WriteTimeout: cfg.GetWriteTimeout(),
			Handler:      grpcHandlerFunc(grpcSrv, mux),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{keyPair},
				NextProtos:   []string{"h2"},
			},
		},
		grpcServer: grpcSrv,
		isSecure:   true,
	}, nil
}

// NewInsecure returns a new insecure server
func NewInsecure(g GRPCServer, cfg InsecureConfig) (*Server, error) {

	grpcSrv := grpc.NewServer([]grpc.ServerOption{}...)
	g.RegisterServer(grpcSrv)

	dialOptions := []grpc.DialOption{grpc.WithInsecure()}

	gwmux := runtime.NewServeMux()
	err := g.RegisterHandlersFromEndpoint(context.Background(), gwmux, cfg.Addr(), dialOptions)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	//mux.Handle("/swagger/", http.StripPrefix("/swagger/", serveJSON(http.Dir("./"))))
	mux.Handle("/", gwmux)

	return &Server{
		httpServer: &http.Server{
			Addr:         cfg.Addr(),
			ReadTimeout:  cfg.GetReadTimeout(),
			WriteTimeout: cfg.GetWriteTimeout(),
			Handler:      mux,
		},
		isSecure:   false,
		grpcServer: grpcSrv,
	}, nil
}

func serveJSON(fs http.FileSystem) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		http.FileServer(fs).ServeHTTP(w, r)
	})
}

func grpcHandlerFunc(grpcSrv *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcSrv.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}
