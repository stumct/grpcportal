# grpcportal

provides an easy to use wrapper around creating a gRPC server and gRPC gateway HTTP server.



## Insecure example

	config := grpcportal.InsecureConfig{Port: 8080}

	s, err := grpcportal.NewInsecure(&mainsvc{}, config)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(s.Serve())

## Secure example with TLS
    config := grpcportal.SecureConfig{
        Hostname: "localhost",
        Port:     8080,
        Cert:     []byte(Cert),
        Key:      []byte(Key),
    }

    s, err := grpcportal.NewSecure(&mainsvc{}, config)
    if err != nil {
        log.Fatal(err)
    }

    log.Fatal(s.Serve())