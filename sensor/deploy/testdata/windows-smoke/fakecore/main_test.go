package main

import (
	"net/http/httptest"
	"testing"
)

func TestAuthorizedRequiresRegisteredSensorIdentity(t *testing.T) {
	state := &coreState{token: sensorToken, sensorID: "registered-windows-sensor"}
	request := httptest.NewRequest("GET", "/api/v1/sensor/auth-check", nil)
	request.Header.Set("Authorization", "Bearer "+sensorToken)
	request.Header.Set("X-Sensor-ID", "registered-windows-sensor")
	if !state.authorized(request) {
		t.Fatal("matching token and registered sensor identity were rejected")
	}

	request.Header.Set("X-Sensor-ID", "different-windows-sensor")
	if state.authorized(request) {
		t.Fatal("valid token was accepted for a different sensor identity")
	}
	request.Header.Set("X-Sensor-ID", "")
	if state.authorized(request) {
		t.Fatal("valid token was accepted without its registered sensor identity")
	}
}
