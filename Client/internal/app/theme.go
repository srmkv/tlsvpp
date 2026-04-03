package app

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type clientTheme struct {
	fyne.Theme
}

func newClientTheme(base fyne.Theme) fyne.Theme {
	return &clientTheme{Theme: base}
}

func (t *clientTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameSuccess {
		return color.NRGBA{R: 24, G: 92, B: 52, A: 255}
	}
	return t.Theme.Color(name, variant)
}
