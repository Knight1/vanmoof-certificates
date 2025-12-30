package main

// API response types
type AuthResponse struct {
	Token string `json:"token"`
}

type AppTokenResponse struct {
	Token string `json:"token"`
}

type BikeData struct {
	Name          string `json:"name"`
	BikeID        int    `json:"id"`
	FrameNumber   string `json:"frameNumber"`
	FrameSerial   string `json:"frameSerial"`
	BleProfile    string `json:"bleProfile"`
	MainEcuSerial string `json:"mainEcuSerial"`
}

type CustomerData struct {
	Data struct {
		Bikes []BikeData `json:"bikes"`
	} `json:"data"`
}

type CertificateRequest struct {
	PublicKey string `json:"public_key"`
}

type CertificateResponse struct {
	Certificate string `json:"certificate"`
}
