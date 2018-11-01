package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"strings"
	"time"
)

//Task - this struct is used to cover Governor's tasks structure
type Task struct {
	ID       string `json:"id"`
	Number   int64  `json:"number"`
	Source   string `json:"source"`
	SourceID string `json:"sourceid"`
	User     string `json:"user"`
	Action   string `json:"action"`
	State    string `json:"state"`
	Email    string `json:"email"`
}

//Token - this struct is used to cover Auth0 token structure
type Token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

//URLUsers - URL to the list of users
var URLUsers = "http://governor.verf.io/api/users/"

var myClient = &http.Client{Timeout: 10 * time.Second}
var currentToken Token
var tokenExpiration time.Time

//GetTickets - returns the list of tickets into []Task.
//
//Takes:
//status - in which state tasks should be.
//action - what action should be in tasks.
//url - URL where list of tickets is available
func GetTickets(status string, action string) *[]Task {

	bearer := auth()
	req, _ := http.NewRequest("GET", URLUsers, nil)
	req.Header.Add("authorization", bearer)

	resp, err := myClient.Do(req)
	if err != nil {
		println("Error:", err)
	}
	defer resp.Body.Close()

	var ticketsTemp []Task
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	respByte := buf.Bytes()
	err = json.Unmarshal(respByte, &ticketsTemp)
	if err != nil {
		println("Error:", err)
	}

	var tickets []Task
	for _, t := range ticketsTemp {
		if t.State == status && t.Action == action {
			tickets = append(tickets, t)
		}
	}
	if tickets != nil {
		fmt.Println("Results All: ", tickets)
	}
	return &tickets
}

func auth() string {

	if currentToken.AccessToken != "" && tokenExpiration.After(time.Now()) {
		return currentToken.TokenType + " " + currentToken.AccessToken
	}

	fmt.Println("New token will be generated")
	payload := strings.NewReader("{\"grant_type\":\"client_credentials\",\"client_id\": \"lIJmNudGywMs2JPzhayxCvTvnxb2YnRO\",\"client_secret\": \"IvqFrrtetMVRnj_zahi7nvBkgjolFM5xzTCPVbDyoFW8YmmqLUMB-vw2dHyyy-oG\",\"audience\": \"https://governor.verf.io/api\"}")
	url := "https://verfio.auth0.com/oauth/token"

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		log.Printf("Error creating POST request: %s", err)
	}
	req.Header.Add("content-type", "application/json")

	tokenExpiration = time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error sending POST request: %s", err)
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	respByte := buf.Bytes()
	err = json.Unmarshal(respByte, &currentToken)

	tokenExpiration = tokenExpiration.Add(time.Duration(currentToken.ExpiresIn-60) * time.Second)
	fmt.Println("Token will expire at: ", tokenExpiration)

	return currentToken.TokenType + " " + currentToken.AccessToken
}

//DisableUser - this function disables user provided in Task
func DisableUser(ticket *Task) {

	println("Login: ", ticket.User)
	command := exec.Command("PowerShell", "-Command", "Disable-ADAccount", "-Identity "+ticket.User)
	err := run(command, ticket)
	if err != nil {
		println("Error")
		changeStatus(ticket, "error")
		send(err.Error(), "Error detected "+"For support", "governorandclerk@gmail.com")
		//log.Fatal(err)
	} else {
		send("Account was successfully disabled.", "Disable account: "+ticket.User, ticket.Email)
		changeStatus(ticket, "done")
		println("Action: account was disabled")
		fmt.Println("Done")
	}
}

func run(cmd *exec.Cmd, ticket *Task) error {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	err = cmd.Wait()
	if err != nil {
		return err
	}
	return nil
}

func changeStatus(ticket *Task, state string) {
	println("changeStatus: ", state)
	ticket.State = state

	var urlUser = URLUsers + ticket.ID
	j, err := json.Marshal(ticket)
	if err != nil {
		fmt.Println("Error marshaling ticket into JSON")
	}

	t := bytes.NewReader(j)

	bearer := auth()
	req, _ := http.NewRequest("POST", urlUser, t)
	req.Header.Add("authorization", bearer)
	req.Header.Add("contentType", "application/json")
	resp, err := myClient.Do(req)
	if err != nil {
		fmt.Println("Error with POST request")
	}
	defer resp.Body.Close()
}

func send(body string, subject string, email string) {

	from := "governorandclerk@gmail.com"
	pass := readFile("pass.txt")
	to := email

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject:" + subject + "\n\n" +
		body

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}
}

func readFile(filename string) string {

	bs, err := ioutil.ReadFile(filename)

	if err != nil {
		fmt.Println("Error:", err)
		//os.Exit(1)
	}

	pass := string(bs)

	return pass
}
