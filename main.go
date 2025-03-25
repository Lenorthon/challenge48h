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
	"strconv"
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

// Wine représente la structure d'un vin (décodé depuis le JSON).
type Wine struct {
	Points              int     `json:"points"`
	Title               string  `json:"title"`
	Description         string  `json:"description"`
	TasterName          *string `json:"taster_name"`
	TasterTwitterHandle *string `json:"taster_twitter_handle"`
	Price               int     `json:"price"`
	Designation         *string `json:"designation"`
	Variety             string  `json:"variety"`
	Region1             string  `json:"region_1"`
	Region2             *string `json:"region_2"`
	Province            string  `json:"province"`
	Country             string  `json:"country"`
	Winery              string  `json:"winery"`
}

// Purchase représente un achat enregistré dans la base de données.
type Purchase struct {
	ID           int
	WineTitle    string
	Price        int
	PurchaseDate time.Time
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

	// Création de la table des achats
	queryPurchases := `
	CREATE TABLE IF NOT EXISTS purchases (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		wine_title TEXT NOT NULL,
		price INTEGER,
		purchase_date DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(queryPurchases)
	if err != nil {
		log.Fatal("Erreur création table purchases:", err)
	}

	// Chargement des templates HTML (tous les fichiers présents dans /html)
	tmpl = template.Must(template.ParseGlob("html/*.html"))
}

// Home1Handler : page d'accueil non connectée
func Home1Handler(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "home1.html", nil)
}

// Home2Handler : page d'accueil connectée affichant la liste des vins sous forme de vignettes cliquables
func Home2Handler(w http.ResponseWriter, r *http.Request) {
	// Vérifier la session
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/home1", http.StatusSeeOther)
		return
	}

	// Charger le fichier JSON contenant les vins
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

	data := struct {
		Wines []Wine
	}{
		Wines: wines,
	}

	tmpl.ExecuteTemplate(w, "home2.html", data)
}

// DetailsHandler : page de détail d'un vin
func DetailsHandler(w http.ResponseWriter, r *http.Request) {
	// Vérifier la session
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/home1", http.StatusSeeOther)
		return
	}

	// Récupérer l'index du vin dans l'URL (paramètre id)
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "ID du vin manquant.", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID du vin invalide.", http.StatusBadRequest)
		return
	}

	// Charger le fichier JSON
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
	if id < 0 || id >= len(wines) {
		http.Error(w, "Vin non trouvé.", http.StatusNotFound)
		return
	}

	data := struct {
		Wine     Wine
		Index    int
		Username string
	}{
		Wine:     wines[id],
		Index:    id,
		Username: cookie.Value,
	}

	tmpl.ExecuteTemplate(w, "details.html", data)
}

// PurchaseHandler : simule le paiement et affiche la page de succès d'achat
func PurchaseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/home2", http.StatusSeeOther)
		return
	}
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/home1", http.StatusSeeOther)
		return
	}

	idStr := r.FormValue("id")
	if idStr == "" {
		http.Error(w, "ID du vin manquant.", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID du vin invalide.", http.StatusBadRequest)
		return
	}

	// Charger le fichier JSON
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
	if id < 0 || id >= len(wines) {
		http.Error(w, "Vin non trouvé.", http.StatusNotFound)
		return
	}
	wine := wines[id]

	// Enregistrer l'achat dans la base de données
	_, err = db.Exec("INSERT INTO purchases (username, wine_title, price) VALUES (?, ?, ?)", cookie.Value, wine.Title, wine.Price)
	if err != nil {
		http.Error(w, "Erreur lors de l'enregistrement de l'achat.", http.StatusInternalServerError)
		return
	}

	// Affichage de la page de succès d'achat avec les détails du vin
	data := struct {
		Wine     Wine
		Username string
	}{
		Wine:     wine,
		Username: cookie.Value,
	}

	tmpl.ExecuteTemplate(w, "purchase_success.html", data)
}

// AccountHandler : affiche la page "Mon Compte" avec la liste des achats de l'utilisateur
func AccountHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/home1", http.StatusSeeOther)
		return
	}
	username := cookie.Value

	rows, err := db.Query("SELECT id, wine_title, price, purchase_date FROM purchases WHERE username = ?", username)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des achats.", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var purchases []Purchase
	for rows.Next() {
		var p Purchase
		if err := rows.Scan(&p.ID, &p.WineTitle, &p.Price, &p.PurchaseDate); err != nil {
			continue
		}
		purchases = append(purchases, p)
	}

	data := struct {
		Username  string
		Purchases []Purchase
	}{
		Username:  username,
		Purchases: purchases,
	}
	tmpl.ExecuteTemplate(w, "account.html", data)
}

// RegisterHandler : inscription d'un nouvel utilisateur
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

// LoginHandler : connexion d'un utilisateur
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

// LogoutHandler : déconnexion
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
	})
	tmpl.ExecuteTemplate(w, "logout.html", nil)
}

// DeletePurchaseHandler : supprime un achat pour l'utilisateur connecté.
func DeletePurchaseHandler(w http.ResponseWriter, r *http.Request) {
	// Vérifier la méthode POST pour éviter les suppressions accidentelles par GET
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/home1", http.StatusSeeOther)
		return
	}
	username := cookie.Value

	// Récupérer l'ID de l'achat à supprimer
	idStr := r.FormValue("id")
	if idStr == "" {
		http.Error(w, "ID de l'achat manquant.", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID invalide.", http.StatusBadRequest)
		return
	}

	// Supprimer l'achat qui appartient à l'utilisateur connecté
	_, err = db.Exec("DELETE FROM purchases WHERE id = ? AND username = ?", id, username)
	if err != nil {
		http.Error(w, "Erreur lors de la suppression de l'achat.", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func main() {
	// Fichiers statiques (CSS)
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))

	// Routes
	http.HandleFunc("/home1", Home1Handler)
	http.HandleFunc("/home2", Home2Handler)
	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/details", DetailsHandler)
	http.HandleFunc("/purchase", PurchaseHandler)
	http.HandleFunc("/account", AccountHandler)
	http.HandleFunc("/delete_purchase", DeletePurchaseHandler)

	fmt.Println("\033[35m" + "Serveur démarré sur http://localhost" + "\033[0m")
	openbrowser("http://localhost:8080/home1")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
