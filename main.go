package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"sort"
	"regexp"

	"golang.org/x/crypto/ssh"

	"github.com/refaktor/rye/baseio"
	"github.com/refaktor/rye/batteries"
	"github.com/refaktor/rye/contrib"
	"github.com/refaktor/rye/env"
	"github.com/refaktor/rye/evaldo"
	"github.com/refaktor/rye/loader"
)

const (
	maxTimestampDrift = 60 // seconds
)

// Session holds the Rye state for a single user
type Session struct {
	ps         *env.ProgramState
	prevResult env.Object
	mu         sync.Mutex
}

// Server holds all state
type Server struct {
	// map of base64-encoded public key -> parsed ed25519.PublicKey
	allowedKeys map[string]ed25519.PublicKey
	// map of key-id -> P-256 public key
	allowedP256 map[string]P256Pub
	sessions    map[string]map[string]*Session // identity -> name -> session
	mu          sync.RWMutex
	sharedIdx   *env.Idxs
	sharedGen   *env.Gen
	rootCtx     *env.RyeCtx // global root (builtins)
	appCtx      *env.RyeCtx // preloaded application context (child of root)
	debug       bool
}

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	keysFile := flag.String("keys", "authorized_keys.txt", "File with authorized SSH public keys")
	keysP256 := flag.String("keys-p256", "", "JSON file with authorized P-256 public keys (JWK fields: key_id, x, y)")
	preloadFile := flag.String("preload", "", "Rye file to preload in each session")
	debug := flag.Bool("debug", false, "Print incoming code and evaluation results")
	allowNonLocal := flag.Bool("allownonlocal", false, "Listen on all interfaces (0.0.0.0) instead of 127.0.0.1")
	flag.Parse()

	// Load authorized keys
	allowedKeys, err := loadAuthorizedKeys(*keysFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading authorized keys: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d authorized ed25519 keys\n", len(allowedKeys))

	var allowedP256 map[string]P256Pub
	if *keysP256 != "" {
		ap, err := loadAuthorizedP256(*keysP256)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading P-256 keys: %v\n", err)
			os.Exit(1)
		}
		allowedP256 = ap
		fmt.Printf("Loaded %d authorized P-256 keys\n", len(allowedP256))
	} else {
		allowedP256 = make(map[string]P256Pub)
	}

	// Initialize base Rye state (keep original API usage)
	basePs := env.NewProgramState()
	basePs.Dialect = env.Rye2Dialect
	evaldo.RegisterBuiltins(basePs)
	evaldo.RegisterVarBuiltins(basePs)
	// Add full IO + batteries so builtins like 'cmd' are available
	baseio.Register(basePs)
	batteries.RegisterBatteries(basePs)
	contrib.RegisterBuiltins(basePs, &evaldo.BuiltinNames)

	// Create an application context whose parent is the root (builtins)
	rootCtx := basePs.Ctx
	appCtx := env.NewEnv(rootCtx)
	basePs.Ctx = appCtx

	// Optionally preload code (into appCtx)
	if *preloadFile != "" {
		content, err := os.ReadFile(*preloadFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading preload file: %v\n", err)
			os.Exit(1)
		}
		// Use same loading path as /eval to initialize Gen/Idx consistently
		block, genv := loader.LoadStringNoPEG(string(content), false)
		if errObj, ok := block.(env.Error); ok {
			fmt.Fprintf(os.Stderr, "Error parsing preload: %s\n", errObj.Message)
			os.Exit(1)
		}
		blk := block.(env.Block)
		basePs = env.AddToProgramStateNEWWithLocation(basePs, &blk, genv)
		evaldo.EvalBlockInj(basePs, nil, true)
		if basePs.ErrorFlag {
			fmt.Fprintf(os.Stderr, "Error in preload: %s\n", basePs.Res.Inspect(*genv))
			os.Exit(1)
		}
		fmt.Printf("Preloaded %s\n", *preloadFile)
	}

	// Save shared state and contexts for sessions
	server := &Server{
		allowedKeys: allowedKeys,
		allowedP256: allowedP256,
		sessions:    make(map[string]map[string]*Session),
		sharedIdx:   basePs.Idx,
		sharedGen:   basePs.Gen,
		rootCtx:     rootCtx,
		appCtx:      basePs.Ctx,
		debug:       *debug,
	}

	if server.debug {
		fmt.Println("Debug logging enabled")
	}

	// Static UI
	fs := http.FileServer(http.Dir("web"))
	http.Handle("/web/", http.StripPrefix("/web/", fs))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// let other handlers handle
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "web/pocketrye.html")
	})

	// API Routes
	http.HandleFunc("/session", server.handleSession)
	http.HandleFunc("/eval", server.handleEval)
	http.HandleFunc("/list", server.handleList)

	addr := "127.0.0.1:" + *port
	if *allowNonLocal {
		addr = ":" + *port // 0.0.0.0
	}
	if *allowNonLocal {
		fmt.Fprintf(os.Stderr, "\x1b[31mWARNING: Listening on all interfaces (%s). Ensure this host is firewalled and keys are configured.\x1b[0m\n", addr)
	}
	fmt.Printf("Rye in the Sky started on %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// loadAuthorizedKeys reads an authorized_keys file and returns a map of
// base64-encoded public key -> ed25519.PublicKey
func loadAuthorizedKeys(filename string) (map[string]ed25519.PublicKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	keys := make(map[string]ed25519.PublicKey)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse SSH public key format: "ssh-ed25519 <base64> [comment]"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			fmt.Fprintf(os.Stderr, "Warning: invalid key format on line %d\n", lineNum)
			continue
		}

		if parts[0] != "ssh-ed25519" {
			fmt.Fprintf(os.Stderr, "Warning: skipping non-ed25519 key on line %d\n", lineNum)
			continue
		}

		// Parse the SSH public key
		pubKeyBytes, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid base64 on line %d: %v\n", lineNum, err)
			continue
		}

		// Parse as SSH public key to extract the ed25519 key
		sshPubKey, err := ssh.ParsePublicKey(pubKeyBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid SSH key on line %d: %v\n", lineNum, err)
			continue
		}

		// Extract the ed25519 public key
		cryptoKey, ok := sshPubKey.(ssh.CryptoPublicKey)
		if !ok {
			fmt.Fprintf(os.Stderr, "Warning: cannot extract crypto key on line %d\n", lineNum)
			continue
		}

		ed25519Key, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			fmt.Fprintf(os.Stderr, "Warning: key is not ed25519 on line %d\n", lineNum)
			continue
		}

		// Store with base64 as key (for lookup by request header)
		keys[parts[1]] = ed25519Key
		fmt.Printf("  Loaded key: %s... (%s)\n", parts[1][:20], parts[len(parts)-1])
	}

	return keys, scanner.Err()
}

// verifyRequestEd25519 verifies the signature and returns identity if valid
func (s *Server) verifyRequestEd25519(r *http.Request, body []byte) (string, error) {
	// Get headers
	pubKeyB64 := r.Header.Get("X-Public-Key")
	timestampStr := r.Header.Get("X-Timestamp")
	signatureB64 := r.Header.Get("X-Signature")

	if pubKeyB64 == "" || timestampStr == "" || signatureB64 == "" {
		return "", fmt.Errorf("missing required headers (X-Public-Key, X-Timestamp, X-Signature)")
	}

	// Check if public key is allowed
	s.mu.RLock()
	pubKey, allowed := s.allowedKeys[pubKeyB64]
	s.mu.RUnlock()

	if !allowed {
		return "", fmt.Errorf("public key not authorized")
	}

	// Verify timestamp (replay protection)
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid timestamp")
	}

	now := time.Now().Unix()
	if math.Abs(float64(now-timestamp)) > maxTimestampDrift {
		return "", fmt.Errorf("timestamp too old or too far in future (drift: %d seconds)", now-timestamp)
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding")
	}

	// Build signed data: METHOD|PATH|TIMESTAMP|BODY
	var bodyStr string
	if len(body) > 0 {
		bodyStr = string(body)
	}
	signedData := fmt.Sprintf("%s|%s|%s|%s", r.Method, r.URL.Path, timestampStr, bodyStr)

	// Verify signature
	if !ed25519.Verify(pubKey, []byte(signedData), signature) {
		return "", fmt.Errorf("invalid signature")
	}

	return "ed25519:" + pubKeyB64, nil
}

// verifyRequestP256 verifies P-256 ECDSA signature (raw r||s 64 bytes)
func (s *Server) verifyRequestP256(r *http.Request, body []byte) (string, error) {
	keyID := r.Header.Get("X-Key-Id")
	timestampStr := r.Header.Get("X-Timestamp")
	signatureB64 := r.Header.Get("X-Signature")
	if keyID == "" || timestampStr == "" || signatureB64 == "" {
		return "", fmt.Errorf("missing required headers (X-Key-Id, X-Timestamp, X-Signature)")
	}
	// Check if key id is allowed
	s.mu.RLock()
	p, allowed := s.allowedP256[keyID]
	s.mu.RUnlock()
	if !allowed {
		return "", fmt.Errorf("key id not authorized")
	}
	// Verify timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid timestamp")
	}
	now := time.Now().Unix()
	if math.Abs(float64(now-timestamp)) > maxTimestampDrift {
		return "", fmt.Errorf("timestamp too old or too far in future (drift: %d seconds)", now-timestamp)
	}
	// Decode signature (expect 64 bytes r||s)
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding")
	}
	if len(sig) != 64 {
		return "", fmt.Errorf("invalid signature length")
	}
	// Build signed data
	var bodyStr string
	if len(body) > 0 {
		bodyStr = string(body)
	}
	signedData := fmt.Sprintf("%s|%s|%s|%s", r.Method, r.URL.Path, timestampStr, bodyStr)
	// Verify
	if !verifyECDSAP256([]byte(signedData), p, sig[:32], sig[32:]) {
		return "", fmt.Errorf("invalid signature")
	}
	return "p256:" + keyID, nil
}

// verifyRequestAny dispatches to appropriate verifier based on headers
func (s *Server) verifyRequestAny(r *http.Request, body []byte) (string, error) {
	if r.Header.Get("X-Public-Key") != "" {
		return s.verifyRequestEd25519(r, body)
	}
	if r.Header.Get("X-Key-Id") != "" {
		return s.verifyRequestP256(r, body)
	}
	return "", fmt.Errorf("missing required headers (ed25519 or p256)")
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// handleSession handles POST /session (create named) and DELETE /session (close named)
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	// Read body first (needed for signature verification)
	body, _ := io.ReadAll(r.Body)

	// Verify signature (ed25519 or p256)
	identity, err := s.verifyRequestAny(r, body)
	if err != nil {
		jsonError(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var req struct{ Name string `json:"name"` }
	if r.Method == http.MethodPost || r.Method == http.MethodDelete {
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Name) == "" {
			jsonError(w, "invalid or missing name", http.StatusBadRequest)
			return
		}
		// validate name
		if !validSessionName(req.Name) {
			jsonError(w, "invalid name: use 1-64 chars [A-Za-z0-9._-]", http.StatusBadRequest)
			return
		}
	}

	switch r.Method {
	case http.MethodPost:
		// Create named session under identity
		s.mu.Lock()
		m, ok := s.sessions[identity]
		if !ok {
			m = make(map[string]*Session)
			s.sessions[identity] = m
		}
		if _, exists := m[req.Name]; exists {
			s.mu.Unlock()
			jsonError(w, "session with this name already exists", http.StatusConflict)
			return
		}

		// Create new program state with cloned app context; parent remains root
		cloned := s.appCtx.Copy().(*env.RyeCtx)
		cloned.Parent = s.rootCtx
		ps := &env.ProgramState{
			Ser:         *env.NewTSeries(make([]env.Object, 0)),
			Ctx:         cloned,
			Idx:         s.sharedIdx,
			Gen:         s.sharedGen,
			Args:        make([]int, 6),
			Stack:       env.NewEyrStack(),
			DeferBlocks: make([]env.Block, 0),
			Dialect:     env.Rye2Dialect,
		}

		m[req.Name] = &Session{ps: ps}
		s.mu.Unlock()

		fmt.Printf("Session created for %s name=%s\n", identity, req.Name)
		jsonOK(w, map[string]string{"message": "session created", "name": req.Name})

	case http.MethodDelete:
		// Close named session
		s.mu.Lock()
		m, ok := s.sessions[identity]
		if !ok {
			s.mu.Unlock()
			jsonError(w, "no sessions for identity", http.StatusBadRequest)
			return
		}
		if _, exists := m[req.Name]; !exists {
			s.mu.Unlock()
			jsonError(w, "no such session", http.StatusNotFound)
			return
		}
		delete(m, req.Name)
		if len(m) == 0 { delete(s.sessions, identity) }
		s.mu.Unlock()

		fmt.Printf("Session closed for %s name=%s\n", identity, req.Name)
		jsonOK(w, map[string]string{"message": "session closed", "name": req.Name})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleList handles POST /list and returns available words in current context for the caller's named session
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	identity, err := s.verifyRequestAny(r, body)
	if err != nil {
		jsonError(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}
	var req struct{ Name string `json:"name"` }
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Name) == "" || !validSessionName(req.Name) {
		jsonError(w, "invalid or missing name", http.StatusBadRequest)
		return
	}
	// Get session (required so list reflects session context)
	s.mu.RLock()
	m := s.sessions[identity]
	session, exists := m[req.Name]
	s.mu.RUnlock()
	if !exists {
		jsonError(w, "no such session", http.StatusNotFound)
		return
	}
	// Collect words from current context using lc\data behavior
	session.mu.Lock()
	defer session.mu.Unlock()

	list := make([]map[string]interface{}, 0, 256)
		if session.ps != nil && session.ps.Ctx != nil {
			blk := session.ps.Ctx.GetWords(*session.ps.Idx)
			for i := 0; i < blk.Series.Len(); i++ {
				if wobj, ok := blk.Series.Get(i).(env.Word); ok {
					name := session.ps.Idx.GetWord(wobj.Index)
					val, exists := session.ps.Ctx.GetCurrent(wobj.Index)
					typeStr := "literal"
					nargs := -1
					if exists && val != nil {
						switch val.Type() {
						case env.BuiltinType:
							if bi, ok2 := val.(env.Builtin); ok2 { nargs = bi.Argsn }
							typeStr = "builtin"
						case env.FunctionType:
							if fn, okf := val.(env.Function); okf { nargs = fn.Argsn }
							typeStr = "function"
						case env.ContextType:
							typeStr = "context"
						default:
							typeStr = "literal"
						}
					}
					list = append(list, map[string]interface{}{"name": name, "nargs": nargs, "type": typeStr})
				}
			}
		}
		typeOrder := map[string]int{"builtin": 0, "function": 1, "context": 2, "literal": 3}
		sort.SliceStable(list, func(i, j int) bool {
			ti := typeOrder[list[i]["type"].(string)]
			tj := typeOrder[list[j]["type"].(string)]
			if ti != tj { return ti < tj }
			ni := list[i]["name"].(string)
			nj := list[j]["name"].(string)
			return ni < nj
		})
		jsonOK(w, list)
}

// handleEval handles POST /eval
func (s *Server) handleEval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Verify signature (either ed25519 or p256)
	identity, err := s.verifyRequestAny(r, body)
	if err != nil {
		jsonError(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Parse request
	var req struct {
		Name string `json:"name"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Name) == "" || !validSessionName(req.Name) {
		jsonError(w, "invalid request body or missing/invalid name", http.StatusBadRequest)
		return
	}
	// Get session
	s.mu.RLock()
	m := s.sessions[identity]
	session, exists := m[req.Name]
	s.mu.RUnlock()

	if !exists {
		jsonError(w, "no such session", http.StatusNotFound)
		return
	}

	// Evaluate (with lock on this session)
	session.mu.Lock()
	defer session.mu.Unlock()

	// Parse code
	if s.debug {
		fmt.Printf("[%s] /eval code: %s\n", identity, req.Code)
	}
	block, genv := loader.LoadStringNoPEG(req.Code, false)

	// Check parse error
	if errObj, ok := block.(env.Error); ok {
		jsonOK(w, map[string]interface{}{
			"error":  errObj.Message,
			"result": nil,
			"stdout": "",
		})
		return
	}

	// Capture stdout
	oldStdout := os.Stdout
	rPipe, wPipe, _ := os.Pipe()
	os.Stdout = wPipe

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, rPipe)
		outC <- buf.String()
	}()

	// Evaluate (keep original API)
	block1 := block.(env.Block)
	session.ps = env.AddToProgramStateNEWWithLocation(session.ps, &block1, genv)
	evaldo.EvalBlockInj(session.ps, session.prevResult, true)

	// Restore stdout
	wPipe.Close()
	os.Stdout = oldStdout
	captured := <-outC
	rPipe.Close()

	// Build response
	resp := map[string]interface{}{
		"result":      session.ps.Res.Inspect(*genv),
		"stdout":      captured,
		"errorFlag":   session.ps.ErrorFlag,
		"failureFlag": session.ps.FailureFlag,
	}
	if s.debug {
		fmt.Printf("[%s] /eval stdout: %q\n", identity, captured)
		fmt.Printf("[%s]       result: %q\n", identity, session.ps.Res.Inspect(*genv))
	}

	session.prevResult = session.ps.Res

	// Reset flags
	session.ps.ReturnFlag = false
	session.ps.ErrorFlag = false
	session.ps.FailureFlag = false

	jsonOK(w, resp)
}

// validSessionName enforces a safe, simple session name policy
var sessionNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
func validSessionName(name string) bool { return sessionNameRe.MatchString(name) }
