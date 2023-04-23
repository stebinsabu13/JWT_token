package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/securecookie"
)

var t *template.Template

var user = map[string]string{
	"Stebin": "Sabu",
}
var jwtkey = []byte(securecookie.GenerateRandomKey(64))

type Credintials struct {
	UserName string
	Password string
}
type Claims struct {
	UserName string
	jwt.RegisteredClaims
}

func indexpage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	username := getSession(r)
	if username == "" {
		err := t.ExecuteTemplate(w, "login.html", "Please login")
		if err != nil {
			fmt.Fprint(w, err)
		}
	} else {
		http.Redirect(w, r, "/homepage", http.StatusFound)
	}
}

func loginhandler(w http.ResponseWriter, r *http.Request) {
	creds := Credintials{UserName: r.FormValue("email"), Password: r.FormValue("password")}
	expectedPassword, ok := user[creds.UserName]
	if !ok || creds.Password != expectedPassword {
		err := t.ExecuteTemplate(w, "login.html", "Invalid Credientials")
		if err != nil {
			fmt.Fprint(w, err)
			return
		}
	} else {
		setSession(creds.UserName, w)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
func setSession(userName string, w http.ResponseWriter) {
	expirationTime := time.Now().Add(30 * time.Minute)
	claims := Claims{UserName: userName, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expirationTime)}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtkey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
func getSession(r *http.Request) string {
	cookie, err := r.Cookie("token")
	if err == nil {
		tknStr := cookie.Value
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtkey, nil
		})
		if err == nil && tkn.Valid {
			return claims.UserName
		} else {
			fmt.Print(err)
		}
	}
	return ""
}
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	userName := getSession(r)
	if userName == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	refresh(w, r)
	err := t.ExecuteTemplate(w, "home.html", userName)
	if err != nil {
		fmt.Fprint(w, err)
	}
}
func refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err == nil {
		tknStr := c.Value
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtkey, nil
		})
		if err == nil && tkn.Valid {
			if time.Until(claims.ExpiresAt.Time) > 30*time.Second {
				return
			}
			setSession(claims.UserName, w)
		} else {
			fmt.Print(err)
		}
	}
}
func logouthandler(w http.ResponseWriter, r *http.Request) {
	clearSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}
func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
}
func main() {
	t = template.Must(template.ParseGlob("static/*.html"))
	http.HandleFunc("/", indexpage)
	http.HandleFunc("/login-submit", loginhandler)
	http.HandleFunc("/homepage", homeHandler)
	http.HandleFunc("/logout", logouthandler)
	http.ListenAndServe(":8080", nil)
}
