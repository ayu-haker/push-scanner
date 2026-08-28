package packager

import (
	"testing"

	"push-scanner/pkg/scanner"
)

func TestNPMPackagerSimulation(t *testing.T) {
	npm := &NPMPackager{}
	files := []scanner.TargetFile{
		{Path: "package.json", Content: []byte(`{"name": "test-pkg", "files": ["dist"]}`)},
		{Path: "dist/index.js", Content: []byte("console.log('test')")},
		{Path: "src/index.ts", Content: []byte("console.log('src')")},
		{Path: ".env", Content: []byte("SECRET=123")},
	}

	stagedFiles, err := npm.Simulate(".", files)
	if err != nil {
		t.Fatalf("NPM simulation error: %v", err)
	}

	stagedMap := make(map[string]bool)
	for _, f := range stagedFiles {
		stagedMap[f.Path] = f.IsStagedForPublish
	}

	if !stagedMap["package.json"] {
		t.Errorf("package.json should always be staged")
	}
	if !stagedMap["dist/index.js"] {
		t.Errorf("dist/index.js should be staged per 'files' config")
	}
	if stagedMap["src/index.ts"] {
		t.Errorf("src/index.ts should NOT be staged when 'files' restricts to dist")
	}
	if stagedMap[".env"] {
		t.Errorf(".env should NEVER be staged for npm publish")
	}
}

func TestPyPIPackagerSimulation(t *testing.T) {
	pypi := &PyPIPackager{}
	files := []scanner.TargetFile{
		{Path: "pyproject.toml", Content: []byte(`[project]\nname = "my-lib"`)},
		{Path: "my_lib/__init__.py", Content: []byte("# init")},
		{Path: ".env", Content: []byte("SECRET=123")},
		{Path: "my_lib/__pycache__/init.pyc", Content: []byte("binary")},
	}

	stagedFiles, err := pypi.Simulate(".", files)
	if err != nil {
		t.Fatalf("PyPI simulation error: %v", err)
	}

	stagedMap := make(map[string]bool)
	for _, f := range stagedFiles {
		stagedMap[f.Path] = f.IsStagedForPublish
	}

	if !stagedMap["pyproject.toml"] {
		t.Errorf("pyproject.toml should always be staged")
	}
	if !stagedMap["my_lib/__init__.py"] {
		t.Errorf("my_lib/__init__.py should be staged")
	}
	if stagedMap[".env"] {
		t.Errorf(".env should NEVER be staged for PyPI")
	}
	if stagedMap["my_lib/__pycache__/init.pyc"] {
		t.Errorf("__pycache__ should NEVER be staged for PyPI")
	}
}

func TestMavenCargoNuGetPackagers(t *testing.T) {
	// Maven
	maven := &MavenPackager{}
	filesMaven := []scanner.TargetFile{
		{Path: "pom.xml", Content: []byte(`<project></project>`)},
		{Path: "src/main/java/App.java", Content: []byte("class App {}")},
		{Path: "target/app.jar", Content: []byte("jar")},
	}
	stagedMaven, _ := maven.Simulate(".", filesMaven)
	if !stagedMaven[0].IsStagedForPublish || !stagedMaven[1].IsStagedForPublish {
		t.Errorf("pom.xml and src/main/java should be staged for Maven")
	}
	if stagedMaven[2].IsStagedForPublish {
		t.Errorf("target/ output directory should be excluded from Maven staging")
	}

	// Cargo
	cargo := &CargoPackager{}
	filesCargo := []scanner.TargetFile{
		{Path: "Cargo.toml", Content: []byte(`[package]`)},
		{Path: "src/main.rs", Content: []byte("fn main() {}")},
		{Path: "target/debug/app", Content: []byte("bin")},
	}
	stagedCargo, _ := cargo.Simulate(".", filesCargo)
	if !stagedCargo[0].IsStagedForPublish || !stagedCargo[1].IsStagedForPublish {
		t.Errorf("Cargo.toml and src/main.rs should be staged for Cargo")
	}
	if stagedCargo[2].IsStagedForPublish {
		t.Errorf("target/ debug binaries should be excluded from Cargo staging")
	}

	// NuGet
	nuget := &NuGetPackager{}
	filesNuGet := []scanner.TargetFile{
		{Path: "App.csproj", Content: []byte(`<Project></Project>`)},
		{Path: "bin/debug/App.dll", Content: []byte("dll")},
	}
	stagedNuGet, _ := nuget.Simulate(".", filesNuGet)
	if !stagedNuGet[0].IsStagedForPublish {
		t.Errorf("App.csproj should be staged for NuGet")
	}
	if stagedNuGet[1].IsStagedForPublish {
		t.Errorf("bin/debug/ should be excluded from NuGet staging")
	}
}
