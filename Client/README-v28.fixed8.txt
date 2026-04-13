v28.fixed8

Исправление совместимости с Fyne:
- убран вызов w.SetMinSize(...) в internal/app/app.go
- окно остаётся изменяемым по размеру через Resize(...) + SetFixedSize(false)
- совместимо с версиями Fyne, где у fyne.Window нет метода SetMinSize
