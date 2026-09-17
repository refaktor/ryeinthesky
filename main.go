package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/refaktor/rye/baseio"
	"github.com/refaktor/rye/batteries"
	"github.com/refaktor/rye/env"
	"github.com/refaktor/rye/evaldo"
	"github.com/refaktor/rye/loader"
)

// Minimal HTTP REPL for Rye with optional sessions and Ed25519-signed requests
// Endpoints:
//   POST   /session        (create session; requires Ed25519 headers)
//   DELETE /session        (close session; requires Ed25519 headers)
//   POST   /eval           ({"code":"...", "ephemeral":true|false}) -> {result, stdout, flags};
//                           if signed, runs in caller's session; if unsigned and ephemeral=true, uses shared state
//   GET    /list           list words visible in the caller's session (signed) or shared state (unsigned fallback)

const maxTimestampDrift = 60 // seconds

// Session holds per-identity state
 type Session struct {
	ps  *env.ProgramState
	mu  sync.Mutex
 }

func main() {
	// Flags: -port, -keys, -preload, -debug, -allownonlocal
	port := "8080"
	keysFile := "authorized_keys.txt"
	preload := ""
	debug := false
	allowNonLocal := false
	// Simple args parser (order-insensitive, --key value or -key value)
	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "-port", "--port":
			if i+1 < len(os.Args) { port = os.Args[i+1]; i++ }
		case "-keys", "--keys":
			if i+1 < len(os.Args) { keysFile = os.Args[i+1]; i++ }
		case "-preload", "--preload":
			if i+1 < len(os.Args) { preload = os.Args[i+1]; i++ }
		case "-debug", "--debug":
			debug = true
		case "-allownonlocal", "--allownonlocal":
			allowNonLocal = true
		}
	}

	// Shared state (used when no session or ephemeral eval)
	shared := newProgramState()

	// Optional preload
	if preload != "" {
		data, err := os.ReadFile(preload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading preload file: %v\n", err)
			os.Exit(1)
		}
		block, genv := loader.LoadStringNoPEG(string(data), false)
		if errObj, ok := block.(env.Error); ok {
			fmt.Fprintf(os.Stderr, "Error parsing preload: %s\n", errObj.Message)
			os.Exit(1)
		}
		blk := block.(env.Block)
		shared = env.AddToProgramStateNEWWithLocation(shared, &blk, genv)
		evaldo.EvalBlockInj(shared, nil, true)
		if shared.ErrorFlag {
			fmt.Fprintf(os.Stderr, "Error in preload: %s\n", shared.Res.Inspect(*genv))
			os.Exit(1)
		}
		fmt.Printf("Preloaded %s\n", preload)
	}

	// Authorized Ed25519 keys (optional; if file missing, no auth will work)
	allowed, _ := loadAuthorizedKeys(keysFile)

	sessions := make(map[string]*Session)
	var sessMu sync.RWMutex

	mux := http.NewServeMux()

	// Create/close session
	mux.HandleFunc("/session", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		identity, err := verifyRequestEd25519(allowed, r, body)
		if err != nil {
			jsonErr(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
			return
		}
		switch r.Method {
		case http.MethodPost:
			sessMu.Lock()
			if _, ok := sessions[identity]; ok {
				sessMu.Unlock()
				jsonErr(w, http.StatusBadRequest, "session already exists")
				return
			}
			sessions[identity] = &Session{ps: newProgramState()}
			sessMu.Unlock()
			jsonOK(w, map[string]string{"message": "session created"})
		case http.MethodDelete:
			sessMu.Lock()
			if _, ok := sessions[identity]; !ok {
				sessMu.Unlock()
				jsonErr(w, http.StatusBadRequest, "no session")
				return
			}
			delete(sessions, identity)
			sessMu.Unlock()
			jsonOK(w, map[string]string{"message": "session closed"})
		default:
			jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})

	// List visible words
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		// Try signed: list from caller's session; else fallback to shared
		var cur *env.ProgramState = nil
		if body, _ := io.ReadAll(r.Body); true {
			if id, err := verifyRequestEd25519(allowed, r, body); err == nil {
				sessMu.RLock()
				if s, ok := sessions[id]; ok {
					s.mu.Lock()
					cur = s.ps
					defer s.mu.Unlock()
				}
				sessMu.RUnlock()
			}
		}
		if cur == nil { cur = shared }
		list := make([]map[string]interface{}, 0, 256)
		if cur != nil && cur.Ctx != nil {
			blk := cur.Ctx.GetWords(*cur.Idx)
			for i := 0; i < blk.Series.Len(); i++ {
				if wobj, ok := blk.Series.Get(i).(env.Word); ok {
					name := cur.Idx.GetWord(wobj.Index)
					val, exists := cur.Ctx.GetCurrent(wobj.Index)
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
		jsonOK(w, list)
	})

	// Eval code; optional ephemeral=true creates a throwaway state per call
	mux.HandleFunc("/eval", func(w http.ResponseWriter, r *http.Request) {
		isDebug := debug
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "method not allowed")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "failed to read body")
			return
		}
		var req struct {
			Code      string `json:"code"`
			Ephemeral bool   `json:"ephemeral"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid json body")
			return
		}

		// Parse code
		if isDebug { fmt.Printf("/eval code: %s\n", req.Code) }
		block, genv := loader.LoadStringNoPEG(req.Code, false)
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

		// Determine state based on signature/session and ephemeral
		var cur *env.ProgramState
		var lockHeld func()
		// If signed, prefer session state
		if id, err := verifyRequestEd25519(allowed, r, body); err == nil {
			sessMu.RLock()
			if s, ok := sessions[id]; ok {
				s.mu.Lock(); cur = s.ps; lockHeld = func(){ s.mu.Unlock() }
			}
			sessMu.RUnlock()
		}
		// Fallbacks: ephemeral fresh state, else shared
		if cur == nil {
			if req.Ephemeral {
				cur = newProgramState()
			} else {
				cur = shared
			}
		}

		// Eval
		blk := block.(env.Block)
		cur = env.AddToProgramStateNEWWithLocation(cur, &blk, genv)
		evaldo.EvalBlockInj(cur, nil, true)

		// If we used session, keep it (cur already points to it). If shared and not ephemeral, shared==cur already.

		// Restore stdout
		wPipe.Close()
		os.Stdout = oldStdout
		captured := <-outC
		rPipe.Close()

		resp := map[string]interface{}{
			"result":      cur.Res.Inspect(*genv),
			"stdout":      captured,
			"errorFlag":   cur.ErrorFlag,
			"failureFlag": cur.FailureFlag,
		}
		if isDebug { fmt.Printf("/eval stdout: %q\n", captured); fmt.Printf("       result: %q\n", cur.Res.Inspect(*genv)) }
		// reset flags for whichever state we used
		cur.ReturnFlag = false
		cur.ErrorFlag = false
		cur.FailureFlag = false
		if lockHeld != nil { lockHeld() }

		jsonOK(w, resp)
	})

	addr := "127.0.0.1:" + port
	if allowNonLocal { addr = ":" + port }
	if allowNonLocal {
		fmt.Fprintf(os.Stderr, "\x1b[31mWARNING: Listening on all interfaces (%s). Ensure this host is firewalled and keys are configured.\x1b[0m\n", addr)
	}
	fmt.Printf("ryeremotes with sessions listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// util: init a ProgramState with builtins and batteries
func newProgramState() *env.ProgramState {
	ps := env.NewProgramState()
	ps.Dialect = env.Rye2Dialect
	evaldo.RegisterBuiltins(ps)
	evaldo.RegisterVarBuiltins(ps)
	baseio.Register(ps)
	batteries.RegisterBatteries(ps)
	return ps
}

// loadAuthorizedKeys parses SSH ed25519 keys from authorized_keys-style file
func loadAuthorizedKeys(filename string) (map[string]ed25519.PublicKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	keys := make(map[string]ed25519.PublicKey)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		parts := strings.Fields(line)
		if len(parts) < 2 || parts[0] != "ssh-ed25519" { continue }
		pubKeyBytes, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil { continue }
		sshPubKey, err := ssh.ParsePublicKey(pubKeyBytes)
		if err != nil { continue }
		cryptoKey, ok := sshPubKey.(ssh.CryptoPublicKey)
		if !ok { continue }
		edKey, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
		if !ok { continue }
		keys[parts[1]] = edKey
	}
	return keys, scanner.Err()
}

// verifyRequestEd25519 validates METHOD|PATH|TIMESTAMP|BODY signed with ed25519
func verifyRequestEd25519(allowed map[string]ed25519.PublicKey, r *http.Request, body []byte) (string, error) {
	pubKeyB64 := r.Header.Get("X-Public-Key")
	ts := r.Header.Get("X-Timestamp")
	sigB64 := r.Header.Get("X-Signature")
	if pubKeyB64 == "" || ts == "" || sigB64 == "" {
		return "", fmt.Errorf("missing required headers (X-Public-Key, X-Timestamp, X-Signature)")
	}
	pubKey, ok := allowed[pubKeyB64]
	if !ok { return "", fmt.Errorf("public key not authorized") }
	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil { return "", fmt.Errorf("invalid timestamp") }
	now := time.Now().Unix()
	if math.Abs(float64(now-timestamp)) > maxTimestampDrift {
		return "", fmt.Errorf("timestamp too old or too far in future")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil { return "", fmt.Errorf("invalid signature encoding") }
	var bodyStr string
	if len(body) > 0 { bodyStr = string(body) }
	signed := fmt.Sprintf("%s|%s|%s|%s", r.Method, r.URL.Path, ts, bodyStr)
	if !ed25519.Verify(pubKey, []byte(signed), sig) {
		return "", fmt.Errorf("invalid signature")
	}
	return "ed25519:" + pubKeyB64, nil
}
