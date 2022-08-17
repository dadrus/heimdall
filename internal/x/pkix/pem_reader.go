package pkix

import "encoding/pem"

type PEMBlockCallback func(idx int, blockType string, headers map[string]string, content []byte) error

func ReadPEM(pemBytes []byte, callback PEMBlockCallback) error {
	var block *pem.Block

	idx := 0
	next := pemBytes

	for {
		block, next = pem.Decode(next)
		if err := callback(idx, block.Type, block.Headers, block.Bytes); err != nil {
			return err
		}

		idx++

		if len(next) == 0 {
			break
		}
	}

	return nil
}
