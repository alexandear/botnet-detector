package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/google/go-github/v69/github"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
)

func main() {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		panic("GITHUB_TOKEN environment variable is not set")
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(context.Background(), ts)

	ghClient := github.NewClient(tc)
	anonymousGHClient := github.NewClient(nil)

	db, err := sql.Open("sqlite3", "file:malicious.sqlite?cache=shared")
	if err != nil {
		panic("Failed to open database: " + err.Error())
	}
	defer db.Close()

	db.SetMaxOpenConns(1)

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS malicious_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user TEXT NOT NULL,
		is_processed BOOLEAN NOT NULL DEFAULT FALSE,
		is_removed BOOLEAN NOT NULL DEFAULT FALSE,
		UNIQUE(user)
	)`)
	if err != nil {
		panic("Failed to create table: " + err.Error())
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS malicious_repositories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repository TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		is_fork INT NOT NULL DEFAULT FALSE,
		FOREIGN KEY(user_id) REFERENCES malicious_users(id),
		UNIQUE(repository, user_id)
		)`)
	if err != nil {
		panic("Failed to create table: " + err.Error())
	}

	_, err = db.Exec(`INSERT OR IGNORE INTO malicious_users (user) VALUES ('lazysmock'), ('unkemptdefe'), ('ultimatepate')`)
	if err != nil {
		panic("Failed to insert initial users: " + err.Error())
	}

	rows, err := db.Query(`SELECT id, user FROM malicious_users WHERE is_processed = FALSE`)
	if err != nil {
		panic("Failed to fetch users: " + err.Error())
	}
	defer rows.Close()

	type User struct {
		ID   int
		Name string
	}

	nonProcessedUsers := map[User]struct{}{}
	for rows.Next() {
		var dbUser User
		if err := rows.Scan(&dbUser.ID, &dbUser.Name); err != nil {
			panic("Failed to scan user: " + err.Error())
		}

		nonProcessedUsers[dbUser] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		panic("Failed to iterate over rows: " + err.Error())
	}

	if err := rows.Close(); err != nil {
		panic("Failed to close rows: " + err.Error())
	}

	for user := range nonProcessedUsers {
		client := ghClient
		if checkUserIsRemoved(client, user.Name) {
			fmt.Printf("User https://github.com/%s is removed\n", user.Name)

			if _, err := db.Exec(`UPDATE malicious_users SET is_removed = TRUE WHERE id = ?`, user.ID); err != nil {
				panic("Failed to mark user as removed: " + err.Error())
			}

			if false {
				// If the user is removed we still can fetch the events using the anonymous client.
				// Perhaps it's a GitHub bug, but it's a good thing for us.
				client = anonymousGHClient
			}
		}

		fmt.Printf("Fetching events for user https://github.com/%s\n", user.Name)
		ev, err := retrieveMaliciousUserEvents(client, user.Name)
		if err != nil {
			fmt.Printf("Failed to fetch events for %v: %v\n", user, err)
			continue
		}

		if len(ev.CreatedRepositories) > 0 {
			fmt.Printf("Inserting %d created repositories for user https://github.com/%s\n", len(ev.CreatedRepositories), user.Name)

			for repo := range ev.CreatedRepositories {
				if _, err := db.Exec("INSERT OR IGNORE INTO malicious_repositories (repository, user_id, is_fork) VALUES (?, ?, ?)", repo, user.ID, false); err != nil {
					panic("Failed to insert created repository: " + err.Error())
				}
			}
		}

		if len(ev.ForkedRepositories) > 0 {
			fmt.Printf("Inserting %d forked repositories for user: https://github.com/%s\n", len(ev.ForkedRepositories), user.Name)

			for repo := range ev.ForkedRepositories {
				if _, err := db.Exec("INSERT OR IGNORE INTO malicious_repositories (repository, user_id, is_fork) VALUES (?, ?, ?)", repo, user.ID, true); err != nil {
					panic("Failed to insert forked repository: " + err.Error())
				}
			}
		}

		if len(ev.RealUsers) > 0 {
			fmt.Printf("Removing %d real users for user: %s\n", len(ev.RealUsers), user.Name)

			for realUser := range ev.RealUsers {
				if _, err := db.Exec("DELETE FROM malicious_users WHERE user = ?", realUser); err != nil {
					panic("Failed to delete real user: " + err.Error())
				}
			}
		}

		if len(ev.BotUsers) > 0 {
			fmt.Printf("Inserting %d watched users for user: https://github.com/%s\n", len(ev.BotUsers), user.Name)

			for watchedUser := range ev.BotUsers {
				if _, err := db.Exec("INSERT OR IGNORE INTO malicious_users (user) VALUES (?)", watchedUser); err != nil {
					panic("Failed to insert watched user: " + err.Error())
				}
			}
		}

		if _, err := db.Exec(`UPDATE malicious_users SET is_processed = TRUE WHERE id = ?`, user.ID); err != nil {
			panic("Failed to update user: " + err.Error())
		}
	}
}

func checkUserIsRemoved(client *github.Client, user string) bool {
	_, resp, err := client.Users.Get(context.Background(), user)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return true
	}
	if err != nil {
		fmt.Printf("Failed to fetch user https://github.com/%s: %v\n", user, err)
		return false
	}
	return false
}

type Event struct {
	CreatedRepositories map[string]struct{}
	ForkedRepositories  map[string]struct{}
	BotUsers            map[string]struct{}
	RealUsers           map[string]struct{}
}

func newEvent() Event {
	return Event{
		CreatedRepositories: map[string]struct{}{},
		ForkedRepositories:  map[string]struct{}{},
		BotUsers:            map[string]struct{}{},
		RealUsers:           map[string]struct{}{},
	}
}

func retrieveMaliciousUserEvents(client *github.Client, user string) (Event, error) {
	ctx := context.Background()
	performedEvents, _, err := client.Activity.ListEventsPerformedByUser(ctx, user, true, nil)
	if err != nil {
		return Event{}, fmt.Errorf("fetching events: %w", err)
	}

	receivedEvents, _, err := client.Activity.ListEventsReceivedByUser(ctx, user, true, nil)
	if err != nil {
		return Event{}, fmt.Errorf("fetching events: %w", err)
	}

	ev := newEvent()
	for _, event := range slices.Concat(performedEvents, receivedEvents) {
		if event.Type == nil {
			continue
		}
		switch *event.Type {
		case "ForkEvent":
			if event.Repo != nil && event.Repo.Name != nil {
				_, name, ok := strings.Cut(*event.Repo.Name, "/")
				if !ok {
					fmt.Println("Wrong repo name:", *event.Repo.Name)
					continue
				}
				ev.ForkedRepositories[name] = struct{}{}
			}
		case "CreateEvent":
			if event.Repo != nil && event.Repo.Name != nil {
				_, name, ok := strings.Cut(*event.Repo.Name, "/")
				if !ok {
					fmt.Println("Wrong repo name:", *event.Repo.Name)
					continue
				}
				ev.CreatedRepositories[name] = struct{}{}
			}
		case "WatchEvent":
			if event.Actor == nil || event.Actor.Login == nil || *event.Actor.Login == user {
				continue
			}
			login := *event.Actor.Login
			// bots have lowercase logins and no additional information
			legitimate := login != strings.ToLower(login) ||
				event.Actor.Company != nil && *event.Actor.Company != "" ||
				event.Actor.Bio != nil && *event.Actor.Bio != "" ||
				event.Actor.Location != nil && *event.Actor.Location != "" ||
				event.Actor.Email != nil && *event.Actor.Email != "" ||
				event.Actor.Blog != nil && *event.Actor.Blog != ""
			if legitimate {
				fmt.Printf("Legitimate user https://github.com/%s is watching the suspicious user https://github.com/%s\n", login, user)
				ev.RealUsers[login] = struct{}{}
				continue
			}
			ev.BotUsers[login] = struct{}{}
		}
	}

	return ev, nil
}
