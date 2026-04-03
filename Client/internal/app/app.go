package app

import (
	"tlsclientnative/internal/state"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/theme"
)

const (
	windowW  float32 = 900
	windowH  float32 = 600
	sidebarW float32 = 200
	mainW    float32 = 700
	mainH    float32 = 600
	pageW    float32 = 680
	pageH    float32 = 490
)

func Run() error {
	cfg, err := state.Load()
	if err != nil {
		return err
	}
	a := fyneapp.NewWithID("io.srmkv.tlsclientnative")
	a.Settings().SetTheme(newClientTheme(theme.DefaultTheme()))
	w := a.NewWindow("TLS Client Linux")
	w.Resize(fyne.NewSize(windowW, windowH))
	w.SetFixedSize(true)
	ui := NewUI(a, w, cfg)
	ui.Build()
	w.ShowAndRun()
	return nil
}
