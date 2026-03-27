package main

import "encoding/json"

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
		UUID  string     `json:"uuid"`
		Bikes []BikeData `json:"bikes"`
	} `json:"data"`
}

// Vehicle Registry API response types (for shared bikes on S5/S6)
type VehicleAccess struct {
	VehicleID  string `json:"vehicle_id"`
	Role       string `json:"role"`
	RiderName  string `json:"rider_name"`
	RiderEmail string `json:"rider_email"`
	SKU        string `json:"sku"`
	BleID      string `json:"ble_id"`
	Name       string `json:"name"`
	BleProfile string `json:"ble_profile"`
	OwnerID    string `json:"owner_id"`
	OwnerName  string `json:"owner_name"`
	OwnerEmail string `json:"owner_email"`
	StartsAt   string `json:"starts_at"`
	ExpiresAt  string `json:"expires_at"`
}

type RiderVehiclesResponse struct {
	RiderID       string          `json:"rider_id"`
	VehicleAccess []VehicleAccess `json:"vehicle_access"`
}

// Bike sharing invitations response
type BikeSharingInvitationsResponse struct {
	Invitations []json.RawMessage `json:"invitations"`
	Hash        string            `json:"hash"`
}

type CertificateRequest struct {
	PublicKey string `json:"public_key"`
}

type CertificateResponse struct {
	Certificate string `json:"certificate"`
}
