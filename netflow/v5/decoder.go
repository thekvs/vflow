//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    decoder.go
//: details: decodes netflow version 9 packets
//: author:  Mehrdad Arshad Rad
//: date:    04/10/2017
//:
//: Licensed under the Apache License, Version 2.0 (the "License");
//: you may not use this file except in compliance with the License.
//: You may obtain a copy of the License at
//:
//:     http://www.apache.org/licenses/LICENSE-2.0
//:
//: Unless required by applicable law or agreed to in writing, software
//: distributed under the License is distributed on an "AS IS" BASIS,
//: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//: See the License for the specific language governing permissions and
//: limitations under the License.
//: ----------------------------------------------------------------------------

package netflow5

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/thekvs/vflow/ipfix"
	"github.com/thekvs/vflow/reader"
)

type nonfatalError error

// PacketHeader represents Netflow v5  packet header
type PacketHeader struct {
	Version   uint16 // Version of Flow Record format exported in this packet
	Count     uint16 // The total number of records in the Export Packet
	SysUpTime uint32 // Time in milliseconds since this device was first booted
	UNIXSecs  uint32 // Time in seconds since 0000 UTC 197
	UNIXNSecs uint32 // Residual nanoseconds since 0000 UTC 1970
	SeqNum    uint32 // Incremental sequence counter of all Export Packets
	EngType   uint8  // Type of flow-switching engine
	EngID     uint8  // Slot number of the flow-switching engine
	SamplInt  uint16 // First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
}

// FieldSpecifier represents field properties
type FieldSpecifier struct {
	ElementID uint16
	Length    uint16
	Type      ipfix.FieldType
}

// DecodedField represents a decoded field
type DecodedField struct {
	ID    uint16
	Value interface{}
}

// Decoder represents Netflow payload and remote address
type Decoder struct {
	raddr  net.IP
	reader *reader.Reader
}

// Message represents Netflow decoded data
type Message struct {
	AgentID  string
	Header   PacketHeader
	DataSets [][]DecodedField
}

var (
	v5FieldSpecifiers = []FieldSpecifier{
		FieldSpecifier{
			ElementID: 8,
			Length:    4,
			Type:      ipfix.FieldTypes["ipv4Address"],
		},
		FieldSpecifier{
			ElementID: 12,
			Length:    4,
			Type:      ipfix.FieldTypes["ipv4Address"],
		},
		FieldSpecifier{
			ElementID: 15,
			Length:    4,
			Type:      ipfix.FieldTypes["ipv4Address"],
		},
		FieldSpecifier{
			ElementID: 10,
			Length:    2,
			Type:      ipfix.FieldTypes["unsigned16"],
		},
		FieldSpecifier{
			ElementID: 14,
			Length:    2,
			Type:      ipfix.FieldTypes["unsigned16"],
		},
		FieldSpecifier{
			ElementID: 2,
			Length:    4,
			Type:      ipfix.FieldTypes["unsigned32"],
		},
		FieldSpecifier{
			ElementID: 1,
			Length:    4,
			Type:      ipfix.FieldTypes["unsigned32"],
		},
		FieldSpecifier{
			ElementID: 22,
			Length:    4,
			Type:      ipfix.FieldTypes["unsigned32"],
		},
		FieldSpecifier{
			ElementID: 21,
			Length:    4,
			Type:      ipfix.FieldTypes["unsigned32"],
		},
		FieldSpecifier{
			ElementID: 7,
			Length:    2,
			Type:      ipfix.FieldTypes["unsigned16"],
		},
		FieldSpecifier{
			ElementID: 11,
			Length:    2,
			Type:      ipfix.FieldTypes["unsigned16"],
		},
		FieldSpecifier{
			ElementID: 210,
			Length:    1,
			Type:      ipfix.FieldTypes["octetArray"],
		},
		FieldSpecifier{
			ElementID: 6,
			Length:    1,
			Type:      ipfix.FieldTypes["unsigned8"],
		},
		FieldSpecifier{
			ElementID: 4,
			Length:    1,
			Type:      ipfix.FieldTypes["unsigned8"],
		},
		FieldSpecifier{
			ElementID: 5,
			Length:    1,
			Type:      ipfix.FieldTypes["unsigned8"],
		},
		FieldSpecifier{
			ElementID: 16,
			Length:    2,
			Type:      ipfix.FieldTypes["unsigned16"],
		},
		FieldSpecifier{
			ElementID: 17,
			Length:    2,
			Type:      ipfix.FieldTypes["unsigned16"],
		},
		FieldSpecifier{
			ElementID: 9,
			Length:    1,
			Type:      ipfix.FieldTypes["unsigned8"],
		},
		FieldSpecifier{
			ElementID: 13,
			Length:    1,
			Type:      ipfix.FieldTypes["unsigned8"],
		},
		FieldSpecifier{
			ElementID: 210,
			Length:    2,
			Type:      ipfix.FieldTypes["octetArray"],
		},
	}
)

//   The Packet Header format is specified as:
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       Version Number          |            Count              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           sysUpTime                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           UNIX Secs                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Sequence Number                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        Source ID                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (h *PacketHeader) unmarshal(r *reader.Reader) error {
	var err error

	if h.Version, err = r.Uint16(); err != nil {
		return err
	}

	if h.Count, err = r.Uint16(); err != nil {
		return err
	}

	if h.SysUpTime, err = r.Uint32(); err != nil {
		return err
	}

	if h.UNIXSecs, err = r.Uint32(); err != nil {
		return err
	}

	if h.UNIXNSecs, err = r.Uint32(); err != nil {
		return err
	}

	if h.SeqNum, err = r.Uint32(); err != nil {
		return err
	}

	if h.EngType, err = r.Uint8(); err != nil {
		return err
	}

	if h.EngID, err = r.Uint8(); err != nil {
		return err
	}

	if h.SamplInt, err = r.Uint16(); err != nil {
		return err
	}

	return nil
}

func (h *PacketHeader) validate() error {
	if h.Version != 5 {
		return fmt.Errorf("invalid netflow version (%d)", h.Version)
	}

	// TODO: needs more validation

	return nil
}

func (d *Decoder) decodeData() ([]DecodedField, error) {
	var (
		fields []DecodedField
		err    error
		b      []byte
	)

	r := d.reader

	for i := 0; i < len(v5FieldSpecifiers); i++ {
		b, err = r.Read(int(v5FieldSpecifiers[i].Length))
		if err != nil {
			return nil, err
		}

		// m, ok := ipfix.InfoModel[ipfix.ElementKey{
		// 	0,
		// 	v5FieldSpecifiers[i].ElementID,
		// }]
		//
		// if !ok {
		// 	return nil, nonfatalError(fmt.Errorf("Netflow element key (%d) not exist",
		// 		v5FieldSpecifiers[i].ElementID))
		// }

		fields = append(fields, DecodedField{
			ID:    v5FieldSpecifiers[i].ElementID,
			Value: ipfix.Interpret(&b, v5FieldSpecifiers[i].Type),
		})
	}

	return fields, nil
}

// NewDecoder constructs a decoder
func NewDecoder(raddr net.IP, b []byte) *Decoder {
	return &Decoder{raddr, reader.NewReader(b)}
}

func (d *Decoder) Decode() (*Message, error) {
	var msg = new(Message)

	// IPFIX Message Header decoding
	if err := msg.Header.unmarshal(d.reader); err != nil {
		return nil, err
	}
	// IPFIX Message Header validation
	if err := msg.Header.validate(); err != nil {
		return nil, err
	}

	// Add source IP address as Agent ID
	msg.AgentID = d.raddr.String()

	// In case there are multiple non-fatal errors, collect them and report all of them.
	// The rest of the received sets will still be interpreted, until a fatal error is encountered.
	// A non-fatal error is for example an illegal data record or unknown template id.
	var decodeErrors []error
	for d.reader.Len() > 2 {
		if err := d.decodeSet(msg); err != nil {
			switch err.(type) {
			case nonfatalError:
				decodeErrors = append(decodeErrors, err)
			default:
				return nil, err
			}
		}
	}

	return msg, combineErrors(decodeErrors...)
}

func (d *Decoder) decodeSet(msg *Message) error {
	var err error
	startCount := d.reader.ReadCount()

	// the next set should be greater than 4 bytes otherwise that's padding
	for err == nil && (48-(d.reader.ReadCount()-startCount) > 2) && d.reader.Len() > 2 {
		// Data set
		var data []DecodedField
		data, err = d.decodeData()
		if err == nil {
			msg.DataSets = append(msg.DataSets, data)
		}
	}

	// Skip the rest of the set in order to properly continue with the next set
	// This is necessary if the set is padded, has a reserved set ID, or a nonfatal error occurred
	leftoverBytes := 48 - (d.reader.ReadCount() - startCount)
	if leftoverBytes > 0 {
		_, skipErr := d.reader.Read(int(leftoverBytes))
		if skipErr != nil {
			err = skipErr
		}
	}

	return err
}

func combineErrors(errorSlice ...error) (err error) {
	switch len(errorSlice) {
	case 0:
	case 1:
		err = errorSlice[0]
	default:
		var errMsg bytes.Buffer
		errMsg.WriteString("Multiple errors:")
		for _, subError := range errorSlice {
			errMsg.WriteString("\n- " + subError.Error())
		}
		err = errors.New(errMsg.String())
	}
	return
}
