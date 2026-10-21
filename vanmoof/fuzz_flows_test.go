package vanmoof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/ocsp"
)

// A certificate is only valid if each of its fields is right: of its type and in range, not
// expired, for the bike and key expected, and signed by VanMoof (except on S6, whose key
// isn't known). What CheckCertificate says it contains is then what it does.
func FuzzCertificateFields(f *testing.F) {
	ca := trustTestCA(f)
	user := make([]byte, 16)
	user[6], user[8] = 0x40, 0x80
	key, other := make([]byte, 32), make([]byte, 32)
	key[0], other[0] = 1, 2
	inAWeek := uint64(time.Now().Add(7 * 24 * time.Hour).Unix())
	f.Add(uint64(123456), "BBBBBB00001AA", "BBBBBB00001AA", inAWeek, uint64(7), user, key, true)
	f.Add(uint64(1)<<32, "AAAAA000001AA", "AAAAA000001AA", inAWeek, uint64(0x107), user, key, false)
	f.Add(uint64(0), "", "x", uint64(1), uint64(255), user[:15], key[:31], true)
	f.Add(uint64(7), "AAAAA000001AA", "BBBBBB00001AA", uint64(1)<<40, uint64(11), make([]byte, 16), other, false)
	f.Add(uint64(math.MaxUint32), "BBBBBB00001AA", "SVTBKL00001OA", uint64(math.MaxUint32), uint64(0x42), user, key, true)

	f.Fuzz(func(t *testing.T, id uint64, frame, bike string, expiry, role uint64, user, key []byte, signed bool) {
		payload, err := cbor.Marshal(map[string]any{"i": id, "f": frame, "b": bike, "e": expiry, "r": role, "u": user, "p": key})
		if err != nil {
			t.Skip()
		}
		signature := make([]byte, ed25519.SignatureSize)
		if signed {
			signature = ed25519.Sign(ca, payload)
		}
		cert := base64.StdEncoding.EncodeToString(append(signature, payload...))

		res := CheckCertificate(cert, Expect{PublicKey: base64.StdEncoding.EncodeToString(key), Bike: &Bike{FrameNumber: frame}})
		if res.Valid {
			switch {
			case id > math.MaxUint32 || expiry > math.MaxUint32 || role > math.MaxUint8:
				t.Errorf("valid with a number out of range: ID %d, expiry %d, role %d", id, expiry, role)
			case int64(expiry) < time.Now().Unix()-5:
				t.Errorf("valid, but expired at %d", expiry)
			case len(user) != 16 || len(key) != 32 || frame == "" || bike == "":
				t.Errorf("valid with user %x, key %x, frame %q, bike %q", user, key, frame, bike)
			case !signed && !s6FrameNumberRegexp.MatchString(frame):
				t.Errorf("valid without VanMoof's signature, for %q", frame)
			case res.ID != uint32(id) || res.FrameModule != frame || res.BikeModule != bike || res.Expires.Unix() != int64(expiry) ||
				res.Role != uint8(role) || !bytes.Equal(res.UserID, user) || !bytes.Equal(res.PublicKey, key):
				t.Errorf("result %+v isn't what the certificate has", res)
			}
		}
		if !bytes.Equal(key, other) && CheckCertificate(cert, Expect{PublicKey: base64.StdEncoding.EncodeToString(other)}).Valid {
			t.Error("valid for another public key")
		}
	})
}

// Whatever a frame number, invitation GUID or user ID contains, a request with it goes to
// the endpoint meant: the ID is one path segment there, and no segment is empty, "." or
// "..", which would make it another endpoint
func FuzzRequestPaths(f *testing.F) {
	for _, s := range []string{"BBBBBB00001AA", "1eaf0000-0000-3000-8000-0000000000cc", "", ".", "..", "../getCustomerData",
		"a/b", "%2e%2e", "a?b#c", " ", "\x00", "\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		var requested []*url.URL
		respondWith(t, func(r *http.Request) (*http.Response, error) {
			requested = append(requested, r.URL)
			return httpResponse(r, http.StatusNotFound, `{}`), nil
		})
		createCertificate(id, "public", leakAppToken, false)
		acceptBikeSharingInvitation(id, leakAuthToken, false)
		declineBikeSharingInvitation(id, leakAuthToken, false)
		getSharedVehicles(id, leakAppToken, false)

		if id != "" && id != "." && id != ".." && len(requested) != 4 {
			t.Errorf("%d requests for %q, want 4", len(requested), id)
		}
		for _, u := range requested {
			path := u.EscapedPath()
			found := false
			for _, segment := range strings.Split(path, "/")[1:] {
				if segment == "" || segment == "." || segment == ".." {
					t.Errorf("request to %s for %q", path, id)
				}
				if s, err := url.PathUnescape(segment); err == nil && s == id {
					found = true
				}
			}
			if !found {
				t.Errorf("request to %s doesn't have %q as one segment", path, id)
			}
		}
	})
}

// fakeAccount answers like fakeVanMoof for an account whose secrets (refresh token, BLE
// key and passcode, bike message) are secret, and whose personal data (names, phone
// number, MAC address) is personal
func fakeAccount(t *testing.T, secret, personal string) {
	t.Helper()
	ca := trustTestCA(t)
	str := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}
	userID, _ := hex.DecodeString(strings.ReplaceAll(leakUUID, "-", ""))
	name, key := str(personal), str(secret)
	customerData := `{"data":{"uuid":"` + leakUUID + `","name":` + name + `,"phone":` + name + `,"bikes":[` +
		`{"id":1,"name":` + name + `,"frameNumber":"BBBBBB00001AA","bleProfile":"ELECTRIFIED_2022"},` +
		`{"id":2,"name":` + name + `,"frameNumber":"LKY0000002","bleProfile":"ELECTRIFIED_2021"},` +
		`{"id":3,"name":` + name + `,"frameNumber":"LKY0000003","bleProfile":"ELECTRIFIED_2018"}],"bikeDetails":[` +
		`{"id":2,"name":` + name + `,"frameNumber":"LKY0000002","macAddress":` + name + `,"bleProfile":"ELECTRIFIED_2021","key":{"encryptionKey":` + key + `,"passcode":` + key + `}},` +
		`{"id":3,"name":` + name + `,"frameNumber":"LKY0000003","macAddress":` + name + `,"bleProfile":"ELECTRIFIED_2018","key":{"encryptionKey":""}}]}}`

	respondWith(t, func(r *http.Request) (*http.Response, error) {
		var body string
		switch p := r.URL.Path; {
		case p == "/v8/authenticate" || p == "/v8/token":
			body = `{"token":"` + leakAuthToken + `","refreshToken":` + key + `}`
		case p == "/v8/getApplicationToken":
			body = `{"token":"` + leakAppToken + `"}`
		case p == "/v8/getCustomerData":
			body = customerData
		case p == "/v8/getBikeSharingInvitations":
			body = `{"invitations":[{"guid":"g1","ownerName":` + name + `,"bikeName":` + name + `,"bleProfile":"ELECTRIFIED_2022"}],"hash":"x"}`
		case p == "/v8/acceptBikeSharingInvitation/g1":
			body = `{"data":{"id":5,"name":` + name + `,"frameNumber":"BBBBBB00005AA","ownerName":` + name + `}}`
		case p == "/v8/declineBikeSharingInvitation/g1":
			body = `{"result":true}`
		case strings.HasPrefix(p, "/v8/getBikeMessages/"):
			body = `[{"content":` + key + `}]`
		case p == "/external/riders/"+leakUUID+"/vehicles":
			body = `{"vehicle_access":[{"vehicle_id":"AAAAA000004AA","name":` + name + `,"rider_name":` + name + `,"owner_name":` + name + `,"ble_profile":"ELECTRIFIED_2025"}]}`
		case strings.HasSuffix(p, "/create_certificate"):
			var req CertificateRequest
			json.NewDecoder(r.Body).Decode(&req)
			fields := testCertFields(strings.Split(p, "/")[2])
			fields["u"], fields["p"] = userID, mustDecode(req.PublicKey)
			body = `{"certificate":"` + testCert(t, ca, fields) + `"}`
		default:
			return httpResponse(r, http.StatusNotFound, `{"error":"not found"}`), nil
		}
		return httpResponse(r, http.StatusOK, body), nil
	})
}

func mustDecode(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// Whatever an account's secrets and personal data are, debug output hides the secrets
// (but a BLE key that -show-keys shows), and -redact also the personal data. The flows
// run twice: with the values, and with others. A value leaks if it shows up more often
// with it than without it, as it is, escaped, or in JSON.
func FuzzNoLeaks(f *testing.F) {
	for _, s := range [][2]string{{"LeakSecret42", "Leaky McLeakface"}, {"1eaf1eaf1eaf1eaf", "C0:FF:EE:00:00:01"},
		{"secret \x1b[2J value", "name \xe2\x80\xae reversed"}, {`with "quotes" and \ `, "<b>&amp;</b>"}} {
		f.Add(s[0], s[1])
	}
	const controlSecret, controlPersonal = "ControlSecretValue", "ControlPersonalValue"
	f.Fuzz(func(t *testing.T, secret, personal string) {
		if len(secret) < 6 || len(personal) < 6 || !utf8.ValidString(secret) || !utf8.ValidString(personal) ||
			strings.Contains(secret, personal) || strings.Contains(personal, secret) ||
			strings.Contains(controlSecret+controlPersonal, secret) || strings.Contains(controlSecret+controlPersonal, personal) {
			t.Skip()
		}
		run := func(secret, personal string, redact bool) string {
			useTempCache(t, "")
			t.Setenv("VANMOOF_PASSWORD", leakPassword) // the environment can't have every secret, e.g. one with a NUL
			fakeAccount(t, secret, personal)
			SetRedaction(redact, false)
			defer SetRedaction(false, false)
			return captureStdout(t, func() {
				opts := Options{BikeFilter: "all", Debug: true, CleartextKeys: true}
				GetCert(leakEmail, opts)
				ShowKeys(leakEmail, ShowKeysAll, opts)
				Invitations(leakEmail, InvitationsAccept, "all", opts)
				if redact {
					ShowSaved(leakEmail, true) // without -redact it shows the keys on purpose
				}
			})
		}
		forms := func(value string) []string {
			j, _ := json.Marshal(value)
			return []string{value, printable(value), strings.Trim(string(j), `"`)}
		}
		leaks := func(out, control, value string) bool {
			for _, form := range forms(value) {
				if strings.Count(out, form) > strings.Count(control, form) {
					return true
				}
			}
			return false
		}
		withoutBLEKeys := func(out string) string {
			lines := strings.Split(out, "\n")
			for i, line := range lines {
				if strings.HasPrefix(line, "bleSecret: ") {
					lines[i] = ""
				}
			}
			return strings.Join(lines, "\n")
		}

		out, control := run(secret, personal, false), run(controlSecret, controlPersonal, false)
		if leaks(withoutBLEKeys(out), withoutBLEKeys(control), secret) {
			t.Errorf("debug output shows the secret %q:\n%s", secret, out)
		}
		out, control = run(secret, personal, true), run(controlSecret, controlPersonal, true)
		for _, value := range []string{secret, personal} {
			if leaks(out, control, value) {
				t.Errorf("-redact output shows %q:\n%s", value, out)
			}
		}
	})
}

// Whatever the account's bikes are named and numbered, their list (-bikes ask) has nothing
// for a terminal to interpret, and any answer selects each bike at most once
func FuzzBikeList(f *testing.F) {
	f.Add("My bike", "BBBBBB00001AA", 42, "Owner", "ask", "1\n")
	f.Add("\x1b[2J\xe2\x80\xae", "LKY\x1b0000003", 0, "\xe2\x80\xae", "ask", "all\n")
	f.Add("", "", -1, "", "1,LKY0000003", "")
	f.Add("two", "BBBBBB00002AA", 2, "", "2", "")
	f.Fuzz(func(t *testing.T, name, frame string, id int, owner, filter, answer string) {
		bikes := []Bike{{BikeID: id, Name: name, FrameNumber: frame, Owner: owner}, {BikeID: 2, Name: "two", FrameNumber: "BBBBBB00002AA"}}
		setStdin(t, answer)
		var selected []Bike
		out := captureStdout(t, func() { selected, _ = selectBikes(bikes, filter) })
		checkSelection(t, bikes, selected)
		if unescaped(out) {
			t.Errorf("list not escaped: %q", out)
		}
	})
}

// Whatever a bike sharing invitation has in it, its listing has nothing for a terminal to
// interpret, and any choice of invitations selects each at most once
func FuzzInvitationList(f *testing.F) {
	f.Add("1eaf0000-0000-3000-8000-0000000000cc", "Owner", "Their bike", "B-05S-E01EU-XX", "ELECTRIFIED_2022", "2026-12-24T12:00:00+0100", "", "1", "")
	f.Add("\x1b[2J", "\xe2\x80\xae", "\x00", "\x1b", "ELECTRIFIED_\x1b", "\xff", "\x07", "", "all\n")
	f.Fuzz(func(t *testing.T, guid, owner, bike, model, profile, expires, ends, selection, answer string) {
		invitations := []Invitation{{GUID: guid, OwnerName: owner, BikeName: bike, ModelName: model, BleProfile: profile, ExpiresAt: expires, EndsAt: ends}, {GUID: "bbbb-2"}}
		if out := captureStdout(t, func() { printInvitations(invitations) }); unescaped(out) {
			t.Errorf("listing not escaped: %q", out)
		}
		setStdin(t, answer)
		var selected []Invitation
		out := captureStdout(t, func() { selected, _ = selectInvitations(invitations, InvitationsAccept, selection) })
		checkSelection(t, invitations, selected)
		if unescaped(out) {
			t.Errorf("question not escaped: %q", out)
		}
	})
}

// What's saved in the cache is what's loaded back, for any account and values
func FuzzCacheRoundTrip(f *testing.F) {
	f.Add("a@example.com", "auth", "app", "refresh", "private", "BBBBBB00001AA", "certificate", 42, uint32(1767668550), "message")
	f.Add("", "", "", "", "", "", "", 0, uint32(0), "")
	f.Add("\x1b", "\xe2\x80\xae", `"`, `\`, "<>&", "\x00", "\t", -1, uint32(math.MaxUint32), "\n")
	f.Fuzz(func(t *testing.T, email, auth, app, refresh, privateKey, frame, cert string, bikeID int, expires uint32, message string) {
		for _, s := range []string{email, auth, app, refresh, privateKey, frame, cert, message} {
			if !utf8.ValidString(s) {
				t.Skip() // JSON can't keep it, and VanMoof's JSON can't have sent it
			}
		}
		useTempCache(t, "")
		tokens := Tokens{AuthToken: auth, AppToken: app, RefreshToken: refresh}
		bike := savedBike{FrameNumber: frame, BikeID: bikeID, Certificate: cert, Expires: time.Unix(int64(expires), 0),
			BikeMessages: []BikeMessage{{Content: message}}}
		captureStdout(t, func() {
			tokenCache.save(email, tokens, false)
			bikeCache.save(email, savedAccount{Key: &savedKeyPair{PrivateKey: privateKey, PublicKey: "public"}, Bikes: []savedBike{bike}}, false)
		})

		if got, _ := tokenCache.load(email, false); got != tokens {
			t.Errorf("tokens %+v loaded as %+v", tokens, got)
		}
		account, _ := bikeCache.load(email, false)
		if account.Key == nil || account.Key.PrivateKey != privateKey || len(account.Bikes) != 1 {
			t.Fatalf("account loaded as %+v", account)
		}
		got := account.Bikes[0]
		if got.FrameNumber != frame || got.BikeID != bikeID || got.Certificate != cert || !got.Expires.Equal(bike.Expires) ||
			len(got.BikeMessages) != 1 || got.BikeMessages[0].Content != message {
			t.Errorf("bike %+v loaded as %+v", bike, got)
		}
	})
}

// The debug analysis of any token has nothing for a terminal to interpret
func FuzzJWTDisplay(f *testing.F) {
	f.Add(`{"alg":"HS256","typ":"JWT"}`, `{"exp":1767668550,"sub":"x","refresh_token":"secret"}`, "c2ln")
	f.Add(`{"alg":"\x1b[2J"}`, `{"name":"\xe2\x80\xae","nested":{"a":["\x07"]}}`, "")
	f.Add("not json", "[]", "\x00")
	f.Fuzz(func(t *testing.T, header, claims, signature string) {
		token := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + "." + signature
		if out := captureStdout(t, func() { validateAndShowJWT(token) }); unescaped(out) {
			t.Errorf("output not escaped: %q", out)
		}
	})
}

// Debug output of a request, whatever its URL, body and response, has nothing for a
// terminal to interpret
func FuzzDebugOutput(f *testing.F) {
	f.Add("x", `{"a":1}`, "100", "99", "1767668550", 200)
	f.Add("\x1b[2J", "\x1b]0;title\x07", "\x1b", "\xe2\x80\xae", "soon", 429)
	f.Add("", "", "", "", "", 500)
	f.Fuzz(func(t *testing.T, query, body, limit, remaining, reset string, status int) {
		if status < 100 || status > 599 {
			t.Skip()
		}
		respondWith(t, func(r *http.Request) (*http.Response, error) {
			resp := httpResponse(r, status, body)
			resp.Header.Set("x-ratelimit-limit", limit)
			resp.Header.Set("x-ratelimit-remaining", remaining)
			resp.Header.Set("x-ratelimit-reset", reset)
			return resp, nil
		})
		out := captureStdout(t, func() {
			doHTTPRequest("POST", apiBaseURL+"/getCustomerData?q="+url.QueryEscape(query), bytes.NewBufferString(body), nil, true)
		})
		if unescaped(out) {
			t.Errorf("output not escaped: %q", out)
		}
	})
}

// Whatever OCSP answers about a revoked certificate, it's never good: not a response for
// another certificate, from another CA, from a certificate of the CA's that isn't for OCSP,
// or that isn't current, nor anything made of them. Only the CA's signature, or that of a
// responder it authorized, makes a response count, and that can't be forged.
func FuzzOCSPResponse(f *testing.F) {
	ca := newCA(f, nil, "Test CA", nil, nil)
	cert, other := newLeaf(f, &ca, "server", nil, nil), newLeaf(f, &ca, "other", nil, nil)
	responder := issue(f, &ca, &x509.Certificate{Subject: pkix.Name{CommonName: "Responder"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}})
	site := issue(f, &ca, &x509.Certificate{Subject: pkix.Name{CommonName: "Another site"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	revoked := ocsp.Response{Status: ocsp.Revoked, SerialNumber: cert.cert.SerialNumber, RevokedAt: time.Now().Add(-time.Hour)}
	good := ocsp.Response{Status: ocsp.Good, SerialNumber: cert.cert.SerialNumber}
	anHourAgo := time.Now().Add(-time.Hour)
	for _, seed := range [][]byte{
		ocspAnswer(ca, nil, revoked),
		ocspAnswer(ca, &responder, revoked),
		ocspAnswer(ca, nil, ocsp.Response{Status: ocsp.Good, SerialNumber: other.cert.SerialNumber}),
		ocspAnswer(ca, &site, good),
		ocspAnswer(newCA(f, nil, "Another CA", nil, nil), nil, good),
		ocspAnswer(ca, nil, ocsp.Response{Status: ocsp.Good, SerialNumber: cert.cert.SerialNumber, ThisUpdate: anHourAgo.Add(-time.Hour), NextUpdate: anHourAgo}),
		ocspAnswer(ca, nil, ocsp.Response{Status: ocsp.Good, SerialNumber: cert.cert.SerialNumber, ThisUpdate: anHourAgo}),
		ocspAnswer(ca, nil, ocsp.Response{Status: ocsp.Unknown, SerialNumber: cert.cert.SerialNumber}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, response []byte) {
		if r := ocspResult(response, cert.cert, ca.cert); r.status == statusGood {
			t.Errorf("a revoked certificate is good: %+v", r)
		}
	})
}

// Whatever CRL a revoked certificate's URL serves, it's never good: not one from another
// CA, one from before it was revoked, one for other certificates of the CA's (another part
// of its CRL, CA certificates, some revocation reasons, other CAs' too), or one with a
// critical extension this package doesn't know (a delta CRL's), nor anything made of them
func FuzzCRL(f *testing.F) {
	const crlURL = "http://ca.example/1.crl"
	ca := newCA(f, nil, "Test CA", nil, nil)
	cert := newLeaf(f, &ca, "server", nil, []string{crlURL})
	anHourAgo := time.Now().Add(-time.Hour)
	revoked := []x509.RevocationListEntry{{SerialNumber: cert.cert.SerialNumber, RevocationTime: anHourAgo}}
	with := func(extensions ...pkix.Extension) []byte {
		return crlOf(ca, x509.RevocationList{ExtraExtensions: extensions})
	}
	for _, seed := range [][]byte{
		crlOf(ca, x509.RevocationList{RevokedCertificateEntries: revoked}),
		crlOf(ca, x509.RevocationList{RevokedCertificateEntries: revoked, ExtraExtensions: []pkix.Extension{idpExtension(fullName(uri(crlURL)), onlyContainsUserCerts)}}),
		crlOf(newCA(f, nil, "Another CA", nil, nil), x509.RevocationList{}),
		crlOf(ca, x509.RevocationList{ThisUpdate: anHourAgo.Add(-time.Hour), NextUpdate: anHourAgo}),
		with(idpExtension(fullName(uri("http://ca.example/2.crl")))),
		with(idpExtension(nil, onlyContainsCACerts)),
		with(idpExtension(nil, onlySomeReasons)),
		with(idpExtension(nil, indirectCRL)),
		with(pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: must(asn1.Marshal(1))}), // deltaCRLIndicator
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return
		}
		if r := crlResult(crl, crlURL, cert.cert, ca.cert); r.status == statusGood {
			t.Errorf("a revoked certificate is good: %+v", r)
		}
	})
}

// Whatever bytes Firefox Remote Settings serves as OneCRL, parsing them never panics, and
// no input can distrust a certificate whose random key and serial it can't name
func FuzzOneCRL(f *testing.F) {
	ca := newCA(f, nil, "Test CA", nil, nil)
	listed := newLeaf(f, &ca, "server", nil, nil)
	unlisted := newLeaf(f, &ca, "unlisted", nil, nil) // not named by any seed, so never distrusted
	for _, seed := range [][]byte{
		oneCRLJSON(),
		oneCRLJSON(oneCRLBySerial(listed.cert)),
		oneCRLJSON(oneCRLByKey(listed.cert)),
		[]byte(`{"data":[{"issuerName":"!!","serialNumber":"!!"}]}`),
		[]byte(`{"data":[{"subject":"","pubKeyHash":""}]}`),
		[]byte("garbage"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		list, err := parseOneCRL(body)
		if err != nil {
			return
		}
		if list.revokes(unlisted.cert) {
			t.Errorf("a certificate no input can name is distrusted")
		}
	})
}
