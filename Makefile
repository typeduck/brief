.PHONY: test

test:
	go1.13 test -v -count=1 ./...
