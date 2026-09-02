//go:build js && wasm

// Command wasm exposes the consensus engine to the browser.
//
// Everything below runs the SAME code the Go tests exercise — this is not a
// re-implementation, a recording, or an animation. When a visitor cuts a link
// in the dashboard, real Ed25519 signatures are verified, a real Raft election
// runs, and the outcome depends on what they actually did. Two visitors who
// click different things get genuinely different results.
//
// That property is the reason the project is worth hosting at all. A
// pre-rendered demo of a distributed systems claim proves nothing; anyone can
// animate a lie.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/Rahu378/crossfault/internal/consensus"
	"github.com/Rahu378/crossfault/internal/crypt"
	"github.com/Rahu378/crossfault/internal/sim"
)

// engine holds the live simulation. Single-threaded: WASM runs on the browser's
// main thread here, and consensus state is not safe for concurrent access.
type engine struct {
	net  *sim.Network
	mode consensus.Mode
	opts sim.Options
}

var eng engine

func modeFromString(s string) consensus.Mode {
	switch s {
	case "prevote":
		return consensus.ModePreVote
	case "crossfault":
		return consensus.ModeCrossFault
	default:
		return consensus.ModeBaseline
	}
}

// reset rebuilds the cluster from scratch. Exposed as crossfaultReset(mode, seed).
func reset(this js.Value, args []js.Value) any {
	mode := consensus.ModeCrossFault
	seed := int64(42)
	if len(args) > 0 && args[0].Type() == js.TypeString {
		mode = modeFromString(args[0].String())
	}
	if len(args) > 1 && args[1].Type() == js.TypeNumber {
		seed = int64(args[1].Int())
	}

	opts := sim.Options{
		Mode:              mode,
		Seed:              seed,
		BaseDelay:         1,
		CrossCloudDelay:   2,
		ElectionTimeout:   10,
		HeartbeatInterval: 3,
		ProbeInterval:     2,
	}
	net, err := sim.New(sim.DefaultCluster(), opts)
	if err != nil {
		return errResult(err.Error())
	}
	eng = engine{net: net, mode: mode, opts: opts}
	return okResult()
}

// step advances the simulation by n ticks (default 1).
func step(this js.Value, args []js.Value) any {
	if eng.net == nil {
		return errResult("engine not initialised")
	}
	n := 1
	if len(args) > 0 && args[0].Type() == js.TypeNumber {
		n = args[0].Int()
	}
	// Cap per call so a runaway UI cannot freeze the tab.
	if n > 500 {
		n = 500
	}
	for i := 0; i < n; i++ {
		eng.net.Step()
	}
	return okResult()
}

// state returns the full simulation state as a JSON string.
//
// JSON rather than a js.Value tree: crossing the WASM/JS boundary field by
// field is far slower than one marshal plus one JSON.parse, and this is called
// every animation frame.
func state(this js.Value, args []js.Value) any {
	if eng.net == nil {
		return "{}"
	}
	b, err := json.Marshal(eng.net.State(eng.mode))
	if err != nil {
		return "{}"
	}
	return string(b)
}

func cut(this js.Value, args []js.Value) any {
	if eng.net == nil || len(args) < 2 {
		return errResult("cut(from, to)")
	}
	eng.net.CutLink(crypt.NodeID(args[0].String()), crypt.NodeID(args[1].String()))
	return okResult()
}

func heal(this js.Value, args []js.Value) any {
	if eng.net == nil || len(args) < 2 {
		return errResult("heal(from, to)")
	}
	eng.net.HealLink(crypt.NodeID(args[0].String()), crypt.NodeID(args[1].String()))
	return okResult()
}

func corrupt(this js.Value, args []js.Value) any {
	if eng.net == nil || len(args) < 2 {
		return errResult("corrupt(from, to)")
	}
	eng.net.CorruptLink(crypt.NodeID(args[0].String()), crypt.NodeID(args[1].String()))
	return okResult()
}

func clean(this js.Value, args []js.Value) any {
	if eng.net == nil || len(args) < 2 {
		return errResult("clean(from, to)")
	}
	eng.net.CleanLink(crypt.NodeID(args[0].String()), crypt.NodeID(args[1].String()))
	return okResult()
}

// propose submits a write to the current leader. Returns an error result when
// there is no leader — which is itself informative: under a livelock, writes
// simply cannot be accepted, and the UI shows that honestly rather than
// pretending the command was queued.
func propose(this js.Value, args []js.Value) any {
	if eng.net == nil || len(args) < 1 {
		return errResult("propose(command)")
	}
	if err := eng.net.Propose(args[0].String()); err != nil {
		return errResult(err.Error())
	}
	return okResult()
}

func okResult() any {
	return map[string]any{"ok": true}
}

func errResult(msg string) any {
	return map[string]any{"ok": false, "error": msg}
}

func main() {
	js.Global().Set("crossfaultReset", js.FuncOf(reset))
	js.Global().Set("crossfaultStep", js.FuncOf(step))
	js.Global().Set("crossfaultState", js.FuncOf(state))
	js.Global().Set("crossfaultCut", js.FuncOf(cut))
	js.Global().Set("crossfaultHeal", js.FuncOf(heal))
	js.Global().Set("crossfaultCorrupt", js.FuncOf(corrupt))
	js.Global().Set("crossfaultClean", js.FuncOf(clean))
	js.Global().Set("crossfaultPropose", js.FuncOf(propose))

	reset(js.Undefined(), []js.Value{})

	// Signal readiness, then block forever so the exported functions stay alive.
	//
	// The invoke is deliberately isolated: syscall/js turns a JavaScript
	// exception into a Go panic, so an error anywhere in the page's ready
	// handler would otherwise kill the engine outright. The front end must not
	// be able to take down the consensus core.
	notifyReady()
	select {}
}

func notifyReady() {
	defer func() {
		if r := recover(); r != nil {
			js.Global().Get("console").Call("error",
				"crossfault: ready handler threw; engine still running:",
				js.ValueOf(fmtPanic(r)))
		}
	}()
	if cb := js.Global().Get("onCrossfaultReady"); cb.Type() == js.TypeFunction {
		cb.Invoke()
	}
}

func fmtPanic(r any) string {
	if err, ok := r.(error); ok {
		return err.Error()
	}
	if s, ok := r.(string); ok {
		return s
	}
	return "unknown panic"
}
