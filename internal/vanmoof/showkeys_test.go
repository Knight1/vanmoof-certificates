package vanmoof

import "testing"

func detail(id int, profile, key string) BikeDetail {
	d := BikeDetail{BikeID: id, BleProfile: profile}
	d.Key.EncryptionKey = key
	return d
}

func TestFilterKeyBikes(t *testing.T) {
	details := []BikeDetail{
		detail(1, "ELECTRIFIED_2021", "00112233445566778899aabbccddeeff"),
		detail(2, "ELECTRIFIED_2021", ""),
		detail(3, "ELECTRIFIED_2023_TRACK_1", "ffeeddccbbaa99887766554433221100"),
		detail(4, "ELECTRIFIED_2022", "00112233445566778899aabbccddeeff"),
		detail(5, "ELECTRIFIED_2025", ""),
	}

	static := filterKeyBikes(details, ShowKeysStatic)
	if len(static) != 2 || static[0].BikeID != 1 || static[1].BikeID != 3 {
		t.Errorf("static: got %+v, want bikes 1 and 3", static)
	}

	all := filterKeyBikes(details, ShowKeysAll)
	if len(all) != 3 || all[0].BikeID != 1 || all[1].BikeID != 2 || all[2].BikeID != 3 {
		t.Errorf("all: got %+v, want bikes 1, 2 and 3", all)
	}
}

func TestIsKnownStaticKeyProfile(t *testing.T) {
	staticProfiles := []string{"ELECTRIFIED_2018", "ELECTRIFIED_2019", "ELECTRIFIED_2020", "ELECTRIFIED_2021", "ELECTRIFIED_2023_TRACK_1"}
	for _, p := range staticProfiles {
		if !isKnownStaticKeyProfile(p) {
			t.Errorf("isKnownStaticKeyProfile(%q) = false, want true", p)
		}
	}

	certProfiles := []string{"ELECTRIFIED_2022", "ELECTRIFIED_2025", "SMARTBIKE_2016", ""}
	for _, p := range certProfiles {
		if isKnownStaticKeyProfile(p) {
			t.Errorf("isKnownStaticKeyProfile(%q) = true, want false", p)
		}
	}
}
