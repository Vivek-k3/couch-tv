//go:build !linux

package uinput

import "errors"

type Device struct{}

func Open(string) (*Device, error) { return nil, errors.New("uinput: only available on Linux/Android") }
func Supported(int) bool           { return false }
func (d *Device) Press(int) error  { return errors.New("uinput: unavailable") }
func (d *Device) Close() error     { return nil }
