package probe

import (
	"errors"
	"testing"

	"github.com/mehmetalitilgen/dpiprisma/internal/packet"
)

func synAckPkt(ttl uint8, id uint16) packet.Captured {
	return packet.Captured{
		IP:  packet.IPv4Header{TTL: ttl, ID: id},
		TCP: packet.TCPHeader{Flags: packet.FlagSYN | packet.FlagACK},
	}
}

func rstPkt(ttl uint8, id uint16) packet.Captured {
	return packet.Captured{
		IP:  packet.IPv4Header{TTL: ttl, ID: id},
		TCP: packet.TCPHeader{Flags: packet.FlagRST},
	}
}

func TestRSTVerdictString(t *testing.T) {
	tests := []struct {
		v    RSTVerdict
		want string
	}{
		{RSTUnknown, "unknown"},
		{RSTConsistent, "consistent"},
		{RSTSuspicious, "suspicious"},
		{RSTForged, "forged"},
		{RSTVerdict(99), "RSTVerdict(99)"},
		{RSTVerdict(-1), "RSTVerdict(-1)"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("RSTVerdict(%d).String() = %q, want %q", int(tt.v), got, tt.want)
		}
	}
}

func TestEstimateHops(t *testing.T) {
	tests := []struct {
		ttl  uint8
		want int
	}{
		{58, 6},
		{57, 7},
		{61, 3},
		{64, 0},
		{65, 63},
		{117, 11},
		{128, 0},
		{250, 5},
	}
	for _, tt := range tests {
		if got := EstimateHops(tt.ttl); got != tt.want {
			t.Errorf("EstimateHops(%d) = %d, want %d", tt.ttl, got, tt.want)
		}
	}
}

func TestAnalyzeRST(t *testing.T) {
	tests := []struct {
		name        string
		synAck, rst packet.Captured
		wantVerdict RSTVerdict
		wantDelta   int
		wantReasons int
	}{
		{"A consistent", synAckPkt(58, 4096), rstPkt(58, 4097), RSTConsistent, 0, 0},
		{"B forged rst", synAckPkt(58, 4096), rstPkt(61, 4097), RSTForged, 3, 1},
		{"C only ip-id odd", synAckPkt(58, 0), rstPkt(58, 1234), RSTSuspicious, 0, 1},
		{"D ttl +1", synAckPkt(58, 100), rstPkt(59, 101), RSTConsistent, 1, 0},
		{"E ttl -1", synAckPkt(58, 100), rstPkt(57, 101), RSTConsistent, -1, 0},
		{"F ttl -2", synAckPkt(58, 100), rstPkt(56, 101), RSTForged, -2, 1},
		{"G ttl and id", synAckPkt(58, 0), rstPkt(61, 1234), RSTForged, 3, 2},
		{"H both ids zero", synAckPkt(58, 0), rstPkt(58, 0), RSTConsistent, 0, 0},
		{"I id wraps", synAckPkt(58, 65530), rstPkt(58, 5), RSTConsistent, 0, 0},
		{"J id goes back", synAckPkt(58, 5), rstPkt(58, 65530), RSTSuspicious, 0, 1},
		{"K id gap 1000", synAckPkt(58, 100), rstPkt(58, 1100), RSTConsistent, 0, 0},
		{"L id gap 1001", synAckPkt(58, 100), rstPkt(58, 1101), RSTSuspicious, 0, 1},
		{"rst with ack flag", synAckPkt(58, 100), packet.Captured{
			IP:  packet.IPv4Header{TTL: 58, ID: 101},
			TCP: packet.TCPHeader{Flags: packet.FlagRST | packet.FlagACK},
		}, RSTConsistent, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AnalyzeRST(tt.synAck, tt.rst)
			if err != nil {
				t.Fatalf("AnalyzeRST() error = %v", err)
			}
			if got.Verdict != tt.wantVerdict {
				t.Errorf("Verdict = %v, want %v (reasons %v)", got.Verdict, tt.wantVerdict, got.Reasons)
			}
			if got.TTLDelta != tt.wantDelta {
				t.Errorf("TTLDelta = %d, want %d", got.TTLDelta, tt.wantDelta)
			}
			if len(got.Reasons) != tt.wantReasons {
				t.Errorf("len(Reasons) = %d, want %d: %v", len(got.Reasons), tt.wantReasons, got.Reasons)
			}
		})
	}
}

func TestAnalyzeRSTFields(t *testing.T) {
	got, err := AnalyzeRST(synAckPkt(58, 4096), rstPkt(61, 1234))
	if err != nil {
		t.Fatal(err)
	}
	if got.SynAckTTL != 58 || got.RSTTTL != 61 {
		t.Errorf("TTLs = %d, %d; want 58, 61", got.SynAckTTL, got.RSTTTL)
	}
	if got.SynAckHops != 6 || got.RSTHops != 3 {
		t.Errorf("hops = %d, %d; want 6, 3", got.SynAckHops, got.RSTHops)
	}
	if got.SynAckID != 4096 || got.RSTID != 1234 {
		t.Errorf("IDs = %d, %d; want 4096, 1234", got.SynAckID, got.RSTID)
	}
}

func TestAnalyzeRSTErrors(t *testing.T) {
	synOnly := packet.Captured{TCP: packet.TCPHeader{Flags: packet.FlagSYN}}
	ackOnly := packet.Captured{TCP: packet.TCPHeader{Flags: packet.FlagACK}}

	if _, err := AnalyzeRST(synOnly, rstPkt(58, 1)); !errors.Is(err, ErrNotSynAck) {
		t.Errorf("SYN without ACK: err = %v, want ErrNotSynAck", err)
	}
	if _, err := AnalyzeRST(synAckPkt(58, 1), ackOnly); !errors.Is(err, ErrNotRST) {
		t.Errorf("ACK instead of RST: err = %v, want ErrNotRST", err)
	}
}
