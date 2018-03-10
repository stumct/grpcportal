# grpcportal

provides an easy to use wrapper around creating a gRPC server and gRPC gateway HTTP server.

## Prerequisites
	go get -u "google.golang.org/grpc"
	go get -u "github.com/grpc-ecosystem/grpc-gateway/runtime"
## Setting Up
Implement the gRPC server as defined in the proto. The server must also implement `RegisterServer` and `RegisterHandlersFromEndpoint` as shown.

    type TestSvc struct{}

    func (s *TestSvc) Test(ctx context.Context, in *pb.TestRequest) (*pb.TestResponse, error) {
        return &pb.TestResponse{Status: "OK"}, nil
    }

    func (s *TestSvc) RegisterServer(srv *grpc.Server) {
        pb.RegisterTestSvcServer(srv, s)
    }

    func (s *TestSvc) RegisterHandlersFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
        return pb.RegisterTestSvcHandlerFromEndpoint(context.Background(), mux, endpoint, opts)
    }

## Starting an Insecure server
An insecure server is the simplest way to get started. All that needs defined in the config is the port.

	testsvc := TestSvc{}

    config := grpcportal.InsecureConfig{Port: 8080}

	s, err := grpcportal.NewInsecure(&testsvc{}, config)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(s.Serve())

## Starting a Secure server with TLS
A Secure server will take the string representation of the `certificate` and the `key`. If you need to generate certificates then a tool such as `cfssl` can be used https://github.com/cloudflare/cfssl

    testsvc := TestSvc{}
    
    config := grpcportal.SecureConfig{
        Hostname: "localhost",
        Port:     8080,
        Cert:     []byte(certificate),
        Key:      []byte(key),
    }

    s, err := grpcportal.NewSecure(&testsvc{}, config)
    if err != nil {
        log.Fatal(err)
    }

    log.Fatal(s.Serve())
