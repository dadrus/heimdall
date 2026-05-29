package pem

import "encoding/pem"

func readPEMBlocks(data []byte) []*pem.Block {
	var blocks []*pem.Block

	for {
		block, next := pem.Decode(data)
		if block == nil {
			break
		}

		blocks = append(blocks, block)
		data = next
	}

	return blocks
}
