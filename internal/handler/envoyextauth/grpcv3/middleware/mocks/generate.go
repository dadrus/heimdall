package mocks

//go:generate protoc --go_out=. --go_opt=paths=source_relative test_service.proto
//go:generate protoc --go-grpc_out=. --go-grpc_opt=paths=source_relative test_service.proto
