ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_FILES = $(shell find . -type f -name '*.go')
TEST_MODULES ?= 

all: build

# Test currently only runs on the modules folder because some of the
# third-party libraries in lib (e.g. http) are failing.
test:
	cd lib/output/test && go test -v ./...
	cd modules && go test -v ./...

update: clean
	go clean -cache
	go get -u all
	go clean -cache
	cd cmd/mysqlscanner && go build -a && cd ../..
	rm -f mysqlscanner
	ln -s cmd/mysqlscanner/mysqlscanner$(EXECUTABLE_EXTENSION) mysqlscanner
	go mod tidy

gofmt:
	goimports -w -l $(GO_FILES)

build: $(GO_FILES)
	cd cmd/mysqlscanner && go build && cd ../..
	rm -f mysqlscanner
	ln -s cmd/mysqlscanner/mysqlscanner$(EXECUTABLE_EXTENSION) mysqlscanner

clean:
	cd cmd/mysqlscanner && go clean
	rm -f mysqlscanner