// Main logic/functionality for the web application.
// This is where you need to implement your own server.
package main

// Reminder that you're not allowed to import anything that isn't part of the Go standard library.
// This includes golang.org/x/
import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
)

func processRegistration(response http.ResponseWriter, request *http.Request) {
	username := request.FormValue("username")
	password := request.FormValue("password")

	// Check if username already exists
	row := db.QueryRow("SELECT username FROM users WHERE username = ?", username)
	var savedUsername string
	err := row.Scan(&savedUsername)
	if err != sql.ErrNoRows {
		response.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(response, "username %s already exists", savedUsername)
		return
	}

	// Generate salt
	const saltSizeBytes = 16
	salt, err := randomByteString(saltSizeBytes)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	hashedPassword := hashPassword(password, salt)

	_, err = db.Exec("INSERT INTO users VALUES (NULL, ?, ?, ?)", username, hashedPassword, salt)

	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	// Set a new session cookie
	initSession(response, username)

	// Redirect to next page
	http.Redirect(response, request, "/", http.StatusFound)
}

func processLoginAttempt(response http.ResponseWriter, request *http.Request) {
	// Retrieve submitted values
	username := request.FormValue("username")
	password := request.FormValue("password")

	row := db.QueryRow("SELECT password, salt FROM users WHERE username = ?", username)

	// Parse database response: check for no response or get values
	var encodedHash, encodedSalt string
	err := row.Scan(&encodedHash, &encodedSalt)
	if err == sql.ErrNoRows {
		response.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(response, "unknown user")
		return
	} else if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	// Hash submitted password with salt to allow for comparison
	submittedPassword := hashPassword(password, encodedSalt)

	// Verify password
	if submittedPassword != encodedHash {
		fmt.Fprintf(response, "incorrect password")
		return
	}

	// Set a new session cookie
	initSession(response, username)

	// Redirect to next page
	http.Redirect(response, request, "/", http.StatusFound)
}

func processLogout(response http.ResponseWriter, request *http.Request) {
	// get the session token cookie
	cookie, err := request.Cookie("session_token")
	// empty assignment to suppress unused variable warning
	_, _ = cookie, err

	// get username of currently logged in user
	username := getUsernameFromCtx(request)
	// empty assignment to suppress unused variable warning
	_ = username

	//////////////////////////////////
	// BEGIN TASK 2: YOUR CODE HERE
	//////////////////////////////////

	sessionToken := cookie.Value
	// TODO: clear the session token cookie in the user's browser
	// HINT: to clear a cookie, set its MaxAge to -1
	http.SetCookie(response, &http.Cookie{
		Name:   "session_token",
		MaxAge: -1,
	})
	// TODO: delete the session from the database
	_, err = db.Exec("DELETE FROM sessions WHERE token = ?", sessionToken)

	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	//////////////////////////////////
	// END TASK 2: YOUR CODE HERE
	//////////////////////////////////

	// redirect to the homepage
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func processUpload(response http.ResponseWriter, request *http.Request, username string) {

	//////////////////////////////////
	// BEGIN TASK 3: YOUR CODE HERE
	//////////////////////////////////

	file, header, err := request.FormFile("file")
	filename := header.Filename
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	b, err := ioutil.ReadAll(file)
	defer file.Close()
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	//check valid filename
	re := regexp.MustCompile("[^a-z0-9A-Z\\.]+")
	match := re.MatchString(filename)

	if match || len(filename) > 50 || len(filename) < 1 {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(response, "Invalid file name")
		return
	}

	d1 := []byte(b)
	// HINT: files should be stored in const filePath = "./files"
	filep := filepath.Join("./files/", username, filename)
	dir := filepath.Join("./files/", username)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.Mkdir(dir, 0700)
	}

	//store file
	err = ioutil.WriteFile(filep, d1, 0644)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	//track in database
	_, err = db.Exec("INSERT INTO files VALUES (NULL, ?, ?, ?, ?)", username, username, filename, filep)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	//////////////////////////////////
	// END TASK 3: YOUR CODE HERE
	//////////////////////////////////
}

// fileInfo helps you pass information to the template
type fileInfo struct {
	Filename  string
	FileOwner string
	FilePath  string
}

func listFiles(response http.ResponseWriter, request *http.Request, username string) {
	files := make([]fileInfo, 0)

	//////////////////////////////////
	// BEGIN TASK 4: YOUR CODE HERE
	//////////////////////////////////

	// TODO: for each of the user's files, add a
	// corresponding fileInfo struct to the files slice.

	rows, err := db.Query("SELECT filename, ownername, filepath FROM files WHERE username = ?", username)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	defer rows.Close()

	for rows.Next() {
		var (
			filename       string
			fileOwner      string
			filePath       string
			fileInfoStruct fileInfo
		)
		if err := rows.Scan(&filename, &fileOwner, &filePath); err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(response, err.Error())
			return
		}
		fileInfoStruct = fileInfo{
			Filename:  filename,
			FileOwner: fileOwner,
			FilePath:  filePath,
		}
		files = append(files, fileInfoStruct)
	}

	//////////////////////////////////
	// END TASK 4: YOUR CODE HERE
	//////////////////////////////////

	data := map[string]interface{}{
		"Username": username,
		"Files":    files,
	}

	tmpl, err := template.ParseFiles("templates/base.html", "templates/list.html")
	if err != nil {
		log.Error(err)
	}
	err = tmpl.Execute(response, data)
	if err != nil {
		log.Error(err)
	}
}

func getFile(response http.ResponseWriter, request *http.Request, username string) {
	fileString := strings.TrimPrefix(request.URL.Path, "/file/")

	_ = fileString

	//////////////////////////////////
	// BEGIN TASK 5: YOUR CODE HERE
	//////////////////////////////////

	row := db.QueryRow("SELECT filepath, filename FROM files WHERE username = ? AND filepath = ?", username, fileString)

	var filepath, filename string
	err := row.Scan(&filepath, &filename)
	if err == sql.ErrNoRows {
		response.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(response, "File not found")
		return
	}

	setNameOfServedFile(response, filename)
	http.ServeFile(response, request, filepath)

	//////////////////////////////////
	// END TASK 5: YOUR CODE HERE
	//////////////////////////////////
}

func setNameOfServedFile(response http.ResponseWriter, fileName string) {
	response.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
}

func processShare(response http.ResponseWriter, request *http.Request, sender string) {
	recipient := request.FormValue("username")
	filename := request.FormValue("filename")
	_ = filename

	if sender == recipient {
		response.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(response, "can't share with yourself")
		return
	}

	//////////////////////////////////
	// BEGIN TASK 6: YOUR CODE HERE
	//////////////////////////////////
	row := db.QueryRow("SELECT username FROM users WHERE username = ?", recipient)

	var username string
	err := row.Scan(&username)
	if err == sql.ErrNoRows {
		response.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(response, "Recipient not found")
		return
	}

	row = db.QueryRow("SELECT ownername, filepath FROM files WHERE username = ? AND filename = ?", sender, filename)

	var fileowner, filepath string
	err = row.Scan(&fileowner, &filepath)
	if err == sql.ErrNoRows || fileowner != sender {
		response.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(response, "Cannot be shared")
		return
	}

	_, err = db.Exec("INSERT INTO files VALUES (NULL, ?, ?, ?, ?)", recipient, sender, filename, filepath)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	//////////////////////////////////
	// END TASK 6: YOUR CODE HERE
	//////////////////////////////////

}

// Initiate a new session for the given username
func initSession(response http.ResponseWriter, username string) {
	// Generate session token
	sessionToken, err := randomByteString(16)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	expires := time.Now().Add(sessionDuration)

	// Store session in database
	_, err = db.Exec("INSERT INTO sessions VALUES (NULL, ?, ?, ?)", username, sessionToken, expires.Unix())
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	// Set cookie with session data
	http.SetCookie(response, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expires,
		SameSite: http.SameSiteStrictMode,
	})
}
