package provider

import (
	"testing"

	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func TestDiscoverSite_Auto_SingleSite(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-1", Name: "Default", InternalReference: "default"},
	}

	site, err := discoverSite(sites, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if site.ID != "site-1" {
		t.Errorf("expected ID 'site-1', got %q", site.ID)
	}
	if site.InternalReference != "default" {
		t.Errorf("expected InternalReference 'default', got %q", site.InternalReference)
	}
}

func TestDiscoverSite_Auto_NoSites(t *testing.T) {
	sites := []unifi.Site{}

	_, err := discoverSite(sites, "auto")
	if err == nil {
		t.Fatal("expected error for no sites")
	}
	if got := err.Error(); !contains(got, "no sites") {
		t.Errorf("expected 'no sites' in error, got: %s", got)
	}
}

func TestDiscoverSite_Auto_MultipleSites(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-1", Name: "Site 1"},
		{ID: "site-2", Name: "Site 2"},
	}

	_, err := discoverSite(sites, "auto")
	if err == nil {
		t.Fatal("expected error for multiple sites")
	}
	if got := err.Error(); !contains(got, "multiple sites") {
		t.Errorf("expected 'multiple sites' in error, got: %s", got)
	}
}

func TestDiscoverSite_ByID(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-abc", Name: "Production", InternalReference: "prod"},
		{ID: "site-xyz", Name: "Staging", InternalReference: "staging"},
	}

	site, err := discoverSite(sites, "site-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if site.ID != "site-xyz" {
		t.Errorf("expected 'site-xyz', got %q", site.ID)
	}
}

func TestDiscoverSite_ByName(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-abc", Name: "Production", InternalReference: "prod"},
	}

	site, err := discoverSite(sites, "Production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if site.ID != "site-abc" {
		t.Errorf("expected 'site-abc', got %q", site.ID)
	}
}

func TestDiscoverSite_ByInternalReference(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-abc", Name: "Production", InternalReference: "prod"},
	}

	site, err := discoverSite(sites, "prod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if site.ID != "site-abc" {
		t.Errorf("expected 'site-abc', got %q", site.ID)
	}
	if site.InternalReference != "prod" {
		t.Errorf("expected InternalReference 'prod', got %q", site.InternalReference)
	}
}

func TestDiscoverSite_NotFound(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-1", Name: "Default", InternalReference: "default"},
	}

	_, err := discoverSite(sites, "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if got := err.Error(); !contains(got, "nonexistent") {
		t.Errorf("expected 'nonexistent' in error, got: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
