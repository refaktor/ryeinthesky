package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"

	"github.com/refaktor/rye/baseio"
	"github.com/refaktor/rye/batteries"
	"github.com/refaktor/rye/env"
	"github.com/refaktor/rye/evaldo"
	"github.com/refaktor/rye/loader"
)

// Minimal HTTP REPL for Rye
//   POST /eval  {"code": "...", "ephemeral": true|false} -> { result, stdout, errorFlag, failureFlag }
//   GET  /list  -> [ {name, nargs, type} ] from current shared context

func main() {
	ps := env.NewProgramState()
	ps.Dialect = env.Rye2Dialect
	evaldo.RegisterBuiltins(ps)
	evaldo.RegisterVarBuiltins(ps)
	baseio.Register(ps)
	batteries.RegisterBatteries(ps)

	mux := http.NewServeMux()
	// List visible words in current shared ProgramState context
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		list := make([]map[string]interface{}, 0, 256)
		if ps != nil && ps.Ctx != nil {
			blk := ps.Ctx.GetWords(*ps.Idx)
			for i := 0; i < blk.Series.Len(); i++ {
				if wobj, ok := blk.Series.Get(i).(env.Word); ok {
					name := ps.Idx.GetWord(wobj.Index)
					val, exists := ps.Ctx.GetCurrent(wobj.Index)
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
	})

	// Eval code; optional ephemeral=true creates a throwaway state per call
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
			Code      string `json:"code"`
			Ephemeral bool   `json:"ephemeral"`
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

		// Choose state: shared or ephemeral
		cur := ps
		if req.Ephemeral {
			cur = env.NewProgramState()
			cur.Dialect = env.Rye2Dialect
			evaldo.RegisterBuiltins(cur)
			evaldo.RegisterVarBuiltins(cur)
			baseio.Register(cur)
			batteries.RegisterBatteries(cur)
		}

		// Eval
		blk := block.(env.Block)
		cur = env.AddToProgramStateNEWWithLocation(cur, &blk, genv)
		evaldo.EvalBlockInj(cur, nil, true)

		// If not ephemeral, keep shared state updated
		if !req.Ephemeral {
			ps = cur
		}

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
		// reset flags for whichever state we used
		cur.ReturnFlag = false
		cur.ErrorFlag = false
		cur.FailureFlag = false

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
