GOGOPROTO = $(GOPATH)/src/github.com/gogo/protobuf

regenerate:
	(protoc --proto_path=$(GOGOPROTO):$(GOGOPROTO)/protobuf:$(GOPATH)/src/:. --gogo_out=. crash.proto)

clean:
	rm crash.pb.go