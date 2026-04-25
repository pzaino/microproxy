package api

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

var routeRegistrationPattern = regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+)\s+([^\"]+)",`)

var expectedControlPlaneRoutes = map[string][]string{
	"/api/v1/health":                {"GET"},
	"/api/v1/config":                {"GET"},
	"/api/v1/providers":             {"GET", "POST"},
	"/api/v1/providers/{providerID}": {"DELETE", "GET", "PATCH", "PUT"},
	"/api/v1/policies":              {"GET"},
	"/api/v1/policies/{policyID}":   {"GET"},
	"/api/v1/routing":               {"GET"},
	"/api/v1/routing/{routeID}":     {"GET"},
	"/api/v1/tenants":               {"GET"},
	"/api/v1/tenants/{tenantID}":    {"GET"},
	"/api/v1/sessions":              {"GET"},
	"/api/v1/sessions/{sessionID}":  {"GET"},
}

type openAPIDoc struct {
	Paths map[string]map[string]any `yaml:"paths"`
}

func TestControlPlaneRouteSnapshot(t *testing.T) {
	routerRoutes, err := extractRouterRoutes()
	if err != nil {
		t.Fatalf("extract router routes: %v", err)
	}

	if diff := diffRouteMaps(expectedControlPlaneRoutes, routerRoutes); diff != "" {
		t.Fatalf("control-plane route snapshot drift detected:\n%s", diff)
	}
}

func TestControlPlaneOpenAPISpecMatchesRouterRoutes(t *testing.T) {
	routerRoutes, err := extractRouterRoutes()
	if err != nil {
		t.Fatalf("extract router routes: %v", err)
	}

	specRoutes, err := extractOpenAPIRoutes()
	if err != nil {
		t.Fatalf("extract openapi routes: %v", err)
	}

	if diff := diffRouteMaps(routerRoutes, specRoutes); diff != "" {
		t.Fatalf("router/openapi route mismatch:\n%s", diff)
	}
}

func extractRouterRoutes() (map[string][]string, error) {
	data, err := os.ReadFile(repoFile("internal/controlplane/api/router.go"))
	if err != nil {
		return nil, err
	}

	routes := map[string]map[string]struct{}{}
	for _, match := range routeRegistrationPattern.FindAllStringSubmatch(string(data), -1) {
		method, path := match[1], match[2]
		if _, ok := routes[path]; !ok {
			routes[path] = map[string]struct{}{}
		}
		routes[path][method] = struct{}{}
	}

	return normalizeRouteMap(routes), nil
}

func extractOpenAPIRoutes() (map[string][]string, error) {
	data, err := os.ReadFile(repoFile("api/controlplane.openapi.yaml"))
	if err != nil {
		return nil, err
	}

	var spec openAPIDoc
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("invalid openapi yaml: %w", err)
	}

	routes := map[string]map[string]struct{}{}
	for path, ops := range spec.Paths {
		for method := range ops {
			upper := strings.ToUpper(strings.TrimSpace(method))
			if upper == "" {
				continue
			}
			if _, ok := routes[path]; !ok {
				routes[path] = map[string]struct{}{}
			}
			routes[path][upper] = struct{}{}
		}
	}

	return normalizeRouteMap(routes), nil
}

func normalizeRouteMap(input map[string]map[string]struct{}) map[string][]string {
	output := make(map[string][]string, len(input))
	for path, methods := range input {
		list := make([]string, 0, len(methods))
		for method := range methods {
			list = append(list, method)
		}
		sort.Strings(list)
		output[path] = list
	}
	return output
}

func diffRouteMaps(expected, actual map[string][]string) string {
	var diff []string

	paths := map[string]struct{}{}
	for p := range expected {
		paths[p] = struct{}{}
	}
	for p := range actual {
		paths[p] = struct{}{}
	}

	sortedPaths := make([]string, 0, len(paths))
	for p := range paths {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	for _, p := range sortedPaths {
		exp, okExp := expected[p]
		act, okAct := actual[p]
		switch {
		case !okExp:
			diff = append(diff, fmt.Sprintf("unexpected path in actual: %s (%v)", p, act))
		case !okAct:
			diff = append(diff, fmt.Sprintf("missing path in actual: %s (%v)", p, exp))
		case strings.Join(exp, ",") != strings.Join(act, ","):
			diff = append(diff, fmt.Sprintf("method mismatch for %s: expected %v, got %v", p, exp, act))
		}
	}

	return strings.Join(diff, "\n")
}

func repoFile(rel string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "../../.."))
	return filepath.Join(repoRoot, rel)
}
