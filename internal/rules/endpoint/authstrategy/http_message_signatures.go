package authstrategy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"time"

	"github.com/offblocks/httpsig"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type SignatureConfig struct {
	TTL   *time.Duration `mapstructure:"ttl"`
	KeyID string         `mapstructure:"key_id" validate:"required"`
}

type HTTPMessageSignatures struct {
	Components []string        `mapstructure:"components" validate:"gt=0,dive,required"`
	Signature  SignatureConfig `mapstructure:"signature"  validate:"required"`
}

func (c *HTTPMessageSignatures) Apply(ctx context.Context, req *http.Request) error {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Applying http_message_signatures strategy to authenticate request")

	// TODO: there is a need to have access to the Signer impl here

	now := time.Now()
	// TODO: tag is the same as iss for jwt and corresponds to signer.name in heimdall's configuration
	tag := "foo"

	var expires time.Time

	if c.Signature.TTL != nil {
		expires = now.Add(*c.Signature.TTL)
	}

	signer := httpsig.NewSigner(
		httpsig.WithSignParams(
			httpsig.ParamKeyID,
			httpsig.ParamAlg,
			httpsig.ParamCreated,
			httpsig.ParamExpires,
			httpsig.ParamNonce,
			httpsig.ParamTag,
		),
		httpsig.WithSignParamValues(&httpsig.SignatureParameters{
			Created: &now,
			Expires: &expires,
			Tag:     &tag,
		}),
		httpsig.WithSignFields(c.Components...),
		// TODO: the below should be resolved via signer (see other todos above)
		//httpsig.WithSignEcdsaP256Sha256("key1", privKey),
	)

	header, err := signer.Sign(httpsig.MessageFromRequest(req))
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed to sign request").CausedBy(err)
	}

	// set the updated headers
	req.Header = header

	return nil
}

func (c *HTTPMessageSignatures) Hash() []byte {
	const int64BytesCount = 8

	hash := sha256.New()

	for _, component := range c.Components {
		hash.Write(stringx.ToBytes(component))
	}

	if c.Signature.TTL != nil {
		ttlBytes := make([]byte, int64BytesCount)
		binary.LittleEndian.PutUint64(ttlBytes, uint64(*c.Signature.TTL))

		hash.Write(ttlBytes)
	}

	hash.Write(stringx.ToBytes(c.Signature.KeyID))

	return hash.Sum(nil)
}
