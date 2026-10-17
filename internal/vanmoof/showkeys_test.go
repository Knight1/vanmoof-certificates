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
		detail(2, "ELECTRIFIED_2021", ""), // no key yet, still a candidate (for the getBikeMessages check)
		detail(3, "ELECTRIFIED_2023_TRACK_1", "ffeeddccbbaa99887766554433221100"),
		detail(4, "ELECTRIFIED_2022", "00112233445566778899aabbccddeeff"), // cert-only (SA5), excluded
		detail(5, "ELECTRIFIED_2025", ""),                                 // cert-only (S6), excluded
	}

	got := filterKeyBikes(details)
	if len(got) != 3 || got[0].BikeID != 1 || got[1].BikeID != 2 || got[2].BikeID != 3 {
		t.Errorf("filterKeyBikes: got %+v, want bikes 1, 2 and 3", got)
	}
}

func TestIsCertOnlyProfile(t *testing.T) {
	certProfiles := []string{"ELECTRIFIED_2022", "ELECTRIFIED_2025"}
	for _, p := range certProfiles {
		if !isCertOnlyProfile(p) {
			t.Errorf("isCertOnlyProfile(%q) = false, want true", p)
		}
	}

	// Every pre-S5 generation is a static-key bike, not just the handful of profiles
	// seen so far: isCertOnlyProfile must only ever exclude S5/A5 and S6.
	staticProfiles := []string{"ELECTRIFIED_2016", "ELECTRIFIED_2017", "ELECTRIFIED_2018", "ELECTRIFIED_2019", "ELECTRIFIED_2020", "ELECTRIFIED_2021", "ELECTRIFIED_2023_TRACK_1", "SMARTBIKE_2016", "SMARTBIKE_2018", ""}
	for _, p := range staticProfiles {
		if isCertOnlyProfile(p) {
			t.Errorf("isCertOnlyProfile(%q) = true, want false", p)
		}
	}
}
