package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"text/template"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"golang.org/x/crypto/bcrypt"
)

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

var db *sql.DB
var tmpl *template.Template

// Wine représente la structure d'un vin dans le fichier JSON.
type Wine struct {
	Points      int     `json:"points"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	TasterName  *string `json:"taster_name"`
	TasterTwitterHandle *string `json:"taster_twitter_handle"`
	Price       int     `json:"price"`
	Designation *string `json:"designation"`
	Variety     string  `json:"variety"`
	Region1     string  `json:"region_1"`
	Region2     *string `json:"region_2"`
	Province    string  `json:"province"`
	Country     string  `json:"country"`
	Winery      string  `json:"winery"`
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

// Page d'accueil connectée (home2) - affichage de la liste des vins
func Home2Handler(w http.ResponseWriter, r *http.Request) {
	// Vérification de la présence du cookie de session
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/home1", http.StatusSeeOther)
		return
	}

	// Ouverture du fichier JSON contenant les vins
	file, err := os.Open("wine-data-set.json")
	if err != nil {
		http.Error(w, "Erreur lors du chargement des données de vin.", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	var wines []Wine
	if err := json.NewDecoder(file).Decode(&wines); err != nil {
		http.Error(w, "Erreur lors du parsing des données de vin.", http.StatusInternalServerError)
		return
	}

	// Transmission des données au template
	data := struct {
		Wines []Wine
	}{
		Wines: wines,
	}

	tmpl.ExecuteTemplate(w, "home2.html", data)
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
		data := struct{ Error string }{Error: "Nom d'utilisateur déjà pris !"}
		tmpl.ExecuteTemplate(w, "register.html", data)
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
		data := struct{ Error string }{Error: "Identifiants incorrects."}
		tmpl.ExecuteTemplate(w, "login.html", data)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		data := struct{ Error string }{Error: "Identifiants incorrects."}
		tmpl.ExecuteTemplate(w, "login.html", data)
		return
	}

	// Création du cookie de session
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
	// Affichage de la page logout indiquant la déconnexion
	tmpl.ExecuteTemplate(w, "logout.html", nil)
}

func main() {
	// Gestion des fichiers statiques (CSS)
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))

	// Routes d'authentification et d'accès
	http.HandleFunc("/home1", Home1Handler)
	http.HandleFunc("/home2", Home2Handler)
	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)

	// Démarrage du serveur
	fmt.Println("\033[35m" + "Serveur démarré sur http://localhost" + "\033[0m")
	openbrowser("http://localhost:8080/home1")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
