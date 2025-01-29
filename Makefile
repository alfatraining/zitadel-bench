build:
	GOOS=linux GOARCH=amd64 go build -o cmd/cli/zitcli github.com/alfatraining/zitadel-bench/cmd/cli

run:
	go run github.com/alfatraining/zitadel-bench/cmd/cli

