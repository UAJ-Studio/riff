// Package wifi holds channel/frequency math shared by the extcap and setup.
package wifi

import "fmt"

type Band int

const (
	Band24 Band = iota
	Band5
	Band6
)

func (b Band) String() string {
	switch b {
	case Band24:
		return "2.4 GHz"
	case Band5:
		return "5 GHz"
	default:
		return "6 GHz"
	}
}

type Channel struct {
	Band Band
	Num  int
	Freq int // control frequency, MHz
}

// Channels lists every channel offered in the UI.
func Channels() []Channel {
	var out []Channel
	for ch := 1; ch <= 14; ch++ {
		out = append(out, Channel{Band24, ch, freq(Band24, ch)})
	}
	for _, ch := range []int{36, 40, 44, 48, 52, 56, 60, 64,
		100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
		149, 153, 157, 161, 165, 169, 173, 177} {
		out = append(out, Channel{Band5, ch, freq(Band5, ch)})
	}
	for ch := 1; ch <= 233; ch += 4 {
		out = append(out, Channel{Band6, ch, freq(Band6, ch)})
	}
	return out
}

func freq(b Band, ch int) int {
	switch b {
	case Band24:
		if ch == 14 {
			return 2484
		}
		return 2407 + 5*ch
	case Band5:
		return 5000 + 5*ch
	default:
		return 5950 + 5*ch
	}
}

// FromFreq finds the channel for a control frequency.
func FromFreq(f int) (Channel, error) {
	for _, c := range Channels() {
		if c.Freq == f {
			return c, nil
		}
	}
	return Channel{}, fmt.Errorf("unknown frequency %d MHz", f)
}

// Center returns the center frequency (MHz) of the width-MHz channel that
// contains control channel c.
func Center(c Channel, width int) (int, error) {
	if width == 20 {
		return c.Freq, nil
	}
	switch c.Band {
	case Band24:
		if width != 40 {
			return 0, fmt.Errorf("2.4 GHz supports only 20/40 MHz")
		}
		if c.Num >= 14 {
			return 0, fmt.Errorf("channel 14 cannot use 40 MHz")
		}
		// HT40+ for low channels, HT40- for high channels.
		if c.Num <= 7 {
			return c.Freq + 10, nil
		}
		return c.Freq - 10, nil
	case Band5:
		if width > 160 {
			return 0, fmt.Errorf("5 GHz supports up to 160 MHz")
		}
		base := 36
		if c.Num >= 149 {
			base = 149
		}
		n := width / 20
		block := (c.Num - base) / (4 * n)
		center := base + block*4*n + 2*(n-1)
		if !valid5(center, width) {
			return 0, fmt.Errorf("channel %d has no %d MHz channel", c.Num, width)
		}
		return 5000 + 5*center, nil
	default:
		n := width / 20
		block := (c.Num - 1) / (4 * n)
		center := 1 + block*4*n + 2*(n-1)
		if center+2*(n-1) > 233 {
			return 0, fmt.Errorf("channel %d has no %d MHz channel", c.Num, width)
		}
		return 5950 + 5*center, nil
	}
}

func valid5(center, width int) bool {
	var ok []int
	switch width {
	case 40:
		ok = []int{38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175}
	case 80:
		ok = []int{42, 58, 106, 122, 138, 155, 171}
	case 160:
		ok = []int{50, 114, 163}
	}
	for _, v := range ok {
		if v == center {
			return true
		}
	}
	return false
}
