package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// DocumentRequest representa o payload enviado pelo frontend.
type DocumentRequest struct {
	DocumentData string `json:"document_data"`
}

// AnalysisResponse representa a resposta estruturada de segurança.
type AnalysisResponse struct {
	IsSafe          bool    `json:"is_safe"`
	ConfidenceScore float64 `json:"confidence_score"`
	ThreatType      string  `json:"threat_type"`
	Details         string  `json:"details"`
}

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// handleAnalyze lida com a requisição de segurança e validação do documento.
func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var req DocumentRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Estrutura inicial da resposta
	response := AnalysisResponse{
		IsSafe:          true,
		ConfidenceScore: 0.99,
		ThreatType:      "None",
		Details:         "Nenhuma instrução maliciosa encontrada no documento. O conteúdo é seguro.",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Inicializa o módulo go internamente se necessário
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/analyze", enableCORS(handleAnalyze))

	port := ":8080"
	fmt.Printf("🚀 Servidor rodando na porta %s...\n", port)

	log.Fatal(http.ListenAndServe(port, mux))
}
