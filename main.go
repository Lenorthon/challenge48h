package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"
	"os/exec"
	"runtime"

	_ "github.com/glebarez/go-sqlite"
	"golang.org/x/time/rate"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var tmpl *template.Template
var limiter = rate.NewLimiter(rate.Every(10*time.Second), 1)

// Middleware de limitation de requêtes
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Trop de requêtes, réessayez plus tard.", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// openbrowser ouvre le navigateur par défaut sur l'URL donnée.
func openbrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default:
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

// Initialisation de la base de données et des templates
func init() {
	var err error
	db, err = sql.Open("sqlite", "auth.db")
	if err != nil {
		log.Fatal("Erreur connexion DB:", err)
	}

	// Création de la table des utilisateurs
	queryUsers := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);
	`
	_, err = db.Exec(queryUsers)
	if err != nil {
		log.Fatal("Erreur création table users:", err)
	}

	// Chargement des templates HTML
	tmpl = template.Must(template.ParseGlob("html/*.html"))
}

// Page d'accueil (home1) - accessible à tous
func Home1Handler(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "home1.html", nil)
}

// Page d'accueil connectée (home2) - protégée
func Home2Handler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/home1", http.StatusSeeOther)
		return
	}
	tmpl.ExecuteTemplate(w, "home2.html", nil)
}

// Handler d'inscription
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl.ExecuteTemplate(w, "register.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "Tous les champs sont requis.", http.StatusBadRequest)
		return
	}

	// Hachage du mot de passe
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Erreur interne.", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
	if err != nil {
		http.Error(w, "Nom d'utilisateur déjà pris.", http.StatusConflict)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Handler de connexion
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err != nil {
		// Si l'utilisateur n'existe pas, on renvoie la page login avec un message d'erreur
		data := struct{ Error string }{Error: "Identifiants incorrects."}
		tmpl.ExecuteTemplate(w, "login.html", data)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		// Si le mot de passe est incorrect, renvoyer la page login avec un message d'erreur
		data := struct{ Error string }{Error: "Identifiants incorrects."}
		tmpl.ExecuteTemplate(w, "login.html", data)
		return
	}

	// Si tout est ok, création du cookie de session et redirection vers home2
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   username,
		Expires: time.Now().Add(24 * time.Hour),
	})
	http.Redirect(w, r, "/home2", http.StatusSeeOther)
}

// Handler de déconnexion
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Suppression du cookie de session
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
	})
	// Affichage de la page logout indiquant que l'utilisateur a bien été déconnecté
	tmpl.ExecuteTemplate(w, "logout.html", nil)
}

func main() {
	// Fichiers statiques
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))

	// Routes d'authentification et d'accès
	http.HandleFunc("/home1", Home1Handler)
	http.HandleFunc("/home2", Home2Handler)
	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)

	// Application du rate limiter
	http.Handle("/", rateLimitMiddleware(http.DefaultServeMux))

	fmt.Println("\033[35m" + "Serveur démarré sur https://localhost" + "\033[0m")

	openbrowser("https://localhost/home1")

	// Utiliser le certificat auto-signé et la clé privée
	err := http.ListenAndServeTLS(":443", "cert.pem", "localhost.key", nil)
	if err != nil {
		fmt.Println("Erreur lors du démarrage du serveur HTTPS:", err)
	}
}
