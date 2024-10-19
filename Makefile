all: exe

exe:
	mkdir -p bin
	go build -o bin ./cmd/*

clean:
	rm -rf bin