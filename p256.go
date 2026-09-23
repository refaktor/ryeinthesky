package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "math/big"
    "os"
)

type P256Pub struct {
    X []byte
    Y []byte
}

type p256JSON struct {
    KeyID string `json:"key_id"`
    Kty   string `json:"kty"`
    Crv   string `json:"crv"`
    X     string `json:"x"`
    Y     string `json:"y"`
}

func loadAuthorizedP256(path string) (map[string]P256Pub, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var items []p256JSON
    if err := json.Unmarshal(data, &items); err != nil {
        return nil, err
    }
    out := make(map[string]P256Pub)
    for _, it := range items {
        if it.Crv != "P-256" || it.Kty != "EC" || it.KeyID == "" || it.X == "" || it.Y == "" {
            continue
        }
        // base64url decode x,y
        xb, err := base64.RawURLEncoding.DecodeString(it.X)
        if err != nil { return nil, fmt.Errorf("decoding x for %s: %w", it.KeyID, err) }
        yb, err := base64.RawURLEncoding.DecodeString(it.Y)
        if err != nil { return nil, fmt.Errorf("decoding y for %s: %w", it.KeyID, err) }
        out[it.KeyID] = P256Pub{X: xb, Y: yb}
    }
    return out, nil
}

func verifyECDSAP256(message []byte, pub P256Pub, rBytes, sBytes []byte) bool {
    curve := elliptic.P256()
    x := new(big.Int).SetBytes(pub.X)
    y := new(big.Int).SetBytes(pub.Y)
    if !curve.IsOnCurve(x, y) {
        return false
    }
    pk := ecdsa.PublicKey{Curve: curve, X: x, Y: y}
    // Hash message per ECDSA with SHA-256
    h := sha256.Sum256(message)
    r := new(big.Int).SetBytes(rBytes)
    s := new(big.Int).SetBytes(sBytes)
    return ecdsa.Verify(&pk, h[:], r, s)
}
