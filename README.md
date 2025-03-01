# botnet-detector

A program to detect all bot users from the article ["Found a group of malicious Go projects injected with trojan"](https://alexandear.github.io/posts/2025-02-28-malicious-go-programs/).

## Running Locally

- Install [Go](https://go.dev/dl/).
- Generate a [GitHub token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) with the following scopes: `[public_repo, read:user]`.
- Run the following command:

```sh
CGO_ENABLED=1 GITHUB_TOKEN=ghp_12345 go run main.go
```
