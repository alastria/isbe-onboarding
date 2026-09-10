// Package html provides HTML rendering capabilities using both Fiber's engine and standard template rendering with security headers.
package html

import (
	"bytes"
	"embed"
	"log/slog"
	"net/http"
	"os"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"

	"github.com/go-sprout/sprout"
	"github.com/go-sprout/sprout/group/all"
)

type RendererFiber struct {
	engine *html.Engine
}

type RendererStd struct {
	engine *html.Engine
}

// NewRendererFiber creates a new HTML renderer to be used in Fiber handlers.
// It supports both embedded templates (in viewsfs) and external templates (in extDir).
// If reload is true, the templates are loaded from the directory specified in extDir.
// If reload is false, the templates are loaded from the embedded directory.
// viewsfs is the filesystem containing the views.
// extDir is the directory containing the external templates.
func NewRendererFiber(reload bool, viewsfs embed.FS, extDir string, extension string) (*RendererFiber, error) {

	engine, err := newEngine(reload, viewsfs, extDir, extension)
	if err != nil {
		return nil, errl.Error(err)
	}

	renderer := &RendererFiber{
		engine: engine,
	}

	return renderer, nil
}

// NewRendererStd creates a new HTML renderer to be used in standard http handlers.
// It supports both embedded templates (in viewsfs) and external templates (in extDir).
// If reload is true, the templates are loaded from the directory specified in extDir.
// If reload is false, the templates are loaded from the embedded directory.
// viewsfs is the filesystem containing the views.
// extDir is the directory containing the external templates.
func NewRendererStd(reload bool, viewsfs embed.FS, extDir string, extension string) (*RendererStd, error) {

	engine, err := newEngine(reload, viewsfs, extDir, extension)
	if err != nil {
		return nil, errl.Error(err)
	}

	renderer := &RendererStd{
		engine: engine,
	}

	return renderer, nil
}

// newEngine creates a new HTML engine.
// It supports both embedded templates (in viewsfs) and external templates (in extDir).
// If reload is true, the templates are loaded from the directory specified in extDir.
// If reload is false, the templates are loaded from the embedded directory.
// viewsfs is the filesystem containing the views.
// extDir is the directory containing the external templates.
// extension is the file extension of the templates.
func newEngine(reload bool, viewsfs embed.FS, extDir string, extension string) (*html.Engine, error) {

	// Check if extDir exists in the os file system
	exists := false
	fi, err := os.Stat(extDir)
	if err == nil && fi.IsDir() {
		exists = true
	}

	// 1. Initialize Sprout handler
	sproutHandler := sprout.New()

	// Add all built-in registries to the handler
	sproutHandler.AddGroups(all.RegistryGroup())

	// 2. Build the Sprout function map
	funcs := sproutHandler.Build()

	if exists {

		// Use the user-provided templates in the external directory
		engine := html.NewFileSystem(http.Dir(extDir), extension)
		engine.Reload(reload)
		engine.AddFuncMap(funcs)

		err = engine.Load()
		if err != nil {
			return nil, errl.Errorf("Failed to load external HTML templates: %w", err)
		}

		slog.Info("Using external HTML templates", "dir", extDir)
		return engine, nil

	}

	engine := html.NewFileSystem(http.FS(viewsfs), extension)
	engine.Reload(reload)
	engine.AddFuncMap(funcs)

	err = engine.Load()
	if err != nil {
		return nil, errl.Errorf("Failed to load embedded HTML templates: %w", err)
	}

	tpls := engine.Templates.Templates()
	for _, tpl := range tpls {
		slog.Info("Loaded template", "name", tpl.Name())
	}

	slog.Info("Using embedded HTML templates")
	return engine, nil
}

// ResponseSecurityHeadersFiber sets the security headers for the response according to best practices
func ResponseSecurityHeadersFiber(c *fiber.Ctx) {

	c.Set("Content-Security-Policy", "frame-ancestors 'none';")
	c.Set("X-Frame-Options", "DENY")
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	c.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	c.Set("Cross-Origin-Opener-Policy", "same-origin")
	c.Set("Cross-Origin-Embedder-Policy", "require-corp")
	c.Set("Cross-Origin-Resource-Policy", "same-site")
	c.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), interest-cohort=()")
	c.Set("X-Powered-By", "webserver")

}

func ResponseSecurityHeadersStd(w http.ResponseWriter) {

	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none';")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-site")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), interest-cohort=()")
	w.Header().Set("X-Powered-By", "webserver")

}

func (h *RendererFiber) Render(c *fiber.Ctx, templateName string, data map[string]any, layout ...string) error {

	c.Set("Content-Type", "text/html; charset=utf-8")
	ResponseSecurityHeadersFiber(c)

	out := &bytes.Buffer{}

	if err := h.engine.Render(out, templateName, data, layout...); err != nil {
		slog.Error("Error rendering template",
			slog.String("error", err.Error()),
		)
		return fiber.NewError(fiber.StatusInternalServerError, "rendering response")
	}

	c.Send(out.Bytes())
	return nil

}

func (h *RendererFiber) RenderToBuffer(templateName string, data any) (*bytes.Buffer, error) {

	out := &bytes.Buffer{}

	if err := h.engine.Render(out, templateName, data); err != nil {
		slog.Error("Error rendering template",
			slog.String("error", err.Error()),
		)
		return nil, errl.Errorf("Error rendering template: %w", err)
	}

	return out, nil

}

func (h *RendererStd) Render(w http.ResponseWriter, templateName string, data map[string]any, layout ...string) error {

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	ResponseSecurityHeadersStd(w)

	out := &bytes.Buffer{}

	if err := h.engine.Render(out, templateName, data, layout...); err != nil {
		slog.Error("Error rendering template",
			slog.String("error", err.Error()),
		)
		return fiber.NewError(fiber.StatusInternalServerError, "rendering response")
	}

	w.Write(out.Bytes())
	return nil

}

func (h *RendererStd) RenderToBuffer(templateName string, data any) (*bytes.Buffer, error) {

	out := &bytes.Buffer{}

	if err := h.engine.Render(out, templateName, data); err != nil {
		slog.Error("Error rendering template",
			slog.String("error", err.Error()),
		)
		return nil, errl.Errorf("Error rendering template: %w", err)
	}

	return out, nil

}
