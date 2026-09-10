package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/refaktor/rye/baseio"
	"github.com/refaktor/rye/batteries"
	"github.com/refaktor/rye/env"
	"github.com/refaktor/rye/evaldo"
	"github.com/refaktor/rye/loader"
)

// Minimal HTTP REPL for Rye
//   POST /eval  {"code": "..."} -> { result, stdout, errorFlag, failureFlag }

func main() {
	ps := env.NewProgramState()
	ps.Dialect = env.Rye2Dialect
	evaldo.RegisterBuiltins(ps)
	evaldo.RegisterVarBuiltins(ps)
	baseio.Register(ps)
	batteries.RegisterBatteries(ps)

	mux := http.NewServeMux()
	mux.HandleFunc("/eval", func(w http.ResponseWriter, r *http.Request) {
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
			Code string `json:"code"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid json body")
			return
		}

		// Parse code
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

		// Eval into shared ProgramState
		blk := block.(env.Block)
		ps = env.AddToProgramStateNEWWithLocation(ps, &blk, genv)
		evaldo.EvalBlockInj(ps, nil, true)

		// Restore stdout
		wPipe.Close()
		os.Stdout = oldStdout
		captured := <-outC
		rPipe.Close()

		resp := map[string]interface{}{
			"result": ps.Res.Inspect(*genv),
			"stdout": captured,
		}
		// reset flags so next eval starts clean
		ps.ReturnFlag = false
		ps.ErrorFlag = false
		ps.FailureFlag = false

		jsonOK(w, resp)
	})

	addr := ":8080"
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
