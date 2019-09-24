all: dedu

.PHONY: all dedu

BUILD_TIMESTAMP=`date +%s | base64 | tr -d '\n'`
BUILD_MACHINE=`uname --all | base64 | tr -d '\n'`
GIT_DESCRIBE=`git describe --dirty --always --tags | base64 | tr -d '\n'`
PROGRAM_NAME=`echo dedu | base64 | tr -d '\n'`

LDFLAGS=-ldflags "-X github.com/steinarvk/orclib/lib/versioninfo.BuildTimestampBase64=${BUILD_TIMESTAMP} -X github.com/steinarvk/orclib/lib/versioninfo.BuildMachineBase64=${BUILD_MACHINE} -X github.com/steinarvk/orclib/lib/versioninfo.GitDescribeBase64=${GIT_DESCRIBE} -X github.com/steinarvk/orclib/lib/versioninfo.ProgramNameBase64=${PROGRAM_NAME}"

gen/dedupb/dedu.pb.go: proto/dedu.proto
	protoc -I proto/ proto/*.proto --go_out=plugins=grpc:gen/dedupb/

dedu: gen/dedupb/dedu.pb.go
	go build ${LDFLAGS} github.com/steinarvk/dedu
