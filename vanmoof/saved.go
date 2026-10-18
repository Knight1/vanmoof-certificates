package vanmoof

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Besides the tokens, the cache keeps each account's getCustomerData response, and the key
// pair its certificates are requested for, along with what the tool got for each of its
// bikes: the latest certificate, the BLE key, and the bike messages waiting for it.
var (
	customerDataCache = cacheFile[json.RawMessage]{name: "customer_data.json", what: "customer data"}
	bikeCache         = cacheFile[savedAccount]{name: "bikes.json", what: "key pair, certificates and BLE keys"}
)

// keysMayBeSaved reports whether the key pair, certificates, BLE keys and customer data
// may be saved: encrypted with VANMOOF_CACHE_KEY, or unencrypted with -cleartext-keys, and
// never with -no-cache
func keysMayBeSaved(opts Options) bool {
	return !opts.NoCache && (getCacheKey() != "" || opts.CleartextKeys)
}

// saveCustomerData saves the account's getCustomerData response, which has its BLE keys,
// if keysMayBeSaved
func saveCustomerData(email string, data *CustomerData, opts Options) {
	if data.raw != nil && keysMayBeSaved(opts) {
		customerDataCache.save(email, data.raw, opts.Debug)
	}
}

// loadAccount returns what the cache holds of the account's key pair and bikes, which is
// nothing with -no-cache
func loadAccount(email string, opts Options) savedAccount {
	if opts.NoCache {
		return savedAccount{}
	}
	account, _ := bikeCache.load(email, opts.Debug)
	return account
}

// saveAccount saves the account's key pair and bikes if keysMayBeSaved, and else says why
// not (unless -no-cache)
func saveAccount(email string, account savedAccount, opts Options) {
	switch {
	case keysMayBeSaved(opts):
		bikeCache.save(email, account, opts.Debug)
	case !opts.NoCache:
		fmt.Println("Note: the key pair, certificates, BLE keys and customer data aren't saved unencrypted: set VANMOOF_CACHE_KEY to encrypt them, or add -cleartext-keys to save them anyway")
	}
}

// keyPair returns the key pair to request certificates for: the saved one, or a new one if
// there's none yet or newKey, which replaces it. It reports whether it's the saved one.
func (a *savedAccount) keyPair(newKey bool) (savedKeyPair, bool, error) {
	if a.Key != nil && !newKey {
		return *a.Key, true, nil
	}
	privateKey, publicKey, err := GenerateED25519()
	if err != nil {
		return savedKeyPair{}, false, err
	}
	a.Key = &savedKeyPair{PrivateKey: privateKey, PublicKey: publicKey, Created: time.Now()}
	return *a.Key, false, nil
}

// bike returns the saved bike with frameNumber, adding it if it isn't saved yet
func (a *savedAccount) bike(frameNumber string) *savedBike {
	for i := range a.Bikes {
		if a.Bikes[i].FrameNumber == frameNumber {
			return &a.Bikes[i]
		}
	}
	a.Bikes = append(a.Bikes, savedBike{FrameNumber: frameNumber})
	return &a.Bikes[len(a.Bikes)-1]
}

// staticBike returns the saved bike of d, a bike with a BLE key, as getCustomerData now
// describes it
func (a *savedAccount) staticBike(d BikeDetail) *savedBike {
	b := a.bike(d.FrameNumber)
	b.BikeID, b.Name, b.Model = d.BikeID, d.Name, Bike{BleProfile: d.BleProfile}.Model()
	return b
}

// setCertificate saves bike's certificate, valid until expires, with the key pair it's for
// (privateKey is "" for a public key given with -pubkey)
func (a *savedAccount) setCertificate(bike Bike, cert string, expires time.Time, publicKey, privateKey string) {
	b := a.bike(bike.FrameNumber)
	b.BikeID, b.Name, b.Model = bike.BikeID, bike.Name, bike.Model()
	b.Certificate, b.Expires, b.PublicKey, b.PrivateKey = cert, expires, publicKey, privateKey
	b.Updated = time.Now()
}

// setBLEKeys saves the BLE keys of the account's bikes that use one (S4 and older), from
// its customer data
func (a *savedAccount) setBLEKeys(details []BikeDetail) {
	for _, d := range filterKeyBikes(details) {
		if d.Key.EncryptionKey == "" || d.FrameNumber == "" {
			continue
		}
		if b := a.staticBike(d); b.BLEKey != d.Key.EncryptionKey {
			b.BLEKey, b.Updated = d.Key.EncryptionKey, time.Now()
		}
	}
}

// setBikeMessages saves the messages waiting for the bike d, replacing the ones before
func (a *savedAccount) setBikeMessages(d BikeDetail, messages []BikeMessage) {
	if d.FrameNumber == "" {
		return
	}
	b := a.staticBike(d)
	b.BikeMessages, b.Updated = messages, time.Now()
}

// ShowSaved prints what the cache holds for the account: the key pair, its bikes'
// certificates, BLE keys and bike messages, and its getCustomerData response. Like the
// regular output it shows the keys, and with -redact hides them and the personal data.
func ShowSaved(email string, debug bool) error {
	accounts, err := bikeCache.loadAll(debug)
	if err != nil {
		return err
	}
	customerData, err := customerDataCache.loadAll(debug)
	if err != nil {
		return err
	}
	account, hasAccount := accounts[email]
	data, hasData := customerData[email]
	if !hasAccount && !hasData {
		fmt.Printf("Nothing saved for %s yet\n", Redact(email))
		return nil
	}

	// What loadAll decoded always encodes again
	doc := must(json.MarshalIndent(struct {
		savedAccount
		CustomerData json.RawMessage `json:"customer_data,omitempty"`
	}{account, data}, "", "  "))
	fmt.Println(showJSON(doc))
	return nil
}

// showJSON returns the JSON document doc for the regular output: as it is, or with -redact
// without secrets and personal data
func showJSON(doc []byte) string {
	if !redactOutput {
		return printableLines(string(doc))
	}
	text := redactJSON(string(doc))
	var out bytes.Buffer
	if err := json.Indent(&out, []byte(text), "", "  "); err != nil {
		return text // an escaped control character, such as \x7f, isn't JSON: shown on one line
	}
	return out.String()
}
