package proxy

import "C"
import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	//"gopkg.in/natefinch/lumberjack.v2"
	"net/http"
	"net/url"
	//"os"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	//"github.com/mbland/hmacauth"
	//"gopkg.in/natefinch/lumberjack.v2"
	"github.com/ayushbpl10/proxy/cookie"
	"github.com/ayushbpl10/proxy/logger"
	"github.com/ayushbpl10/proxy/pkg/apis/options"
	sessionsapi "github.com/ayushbpl10/proxy/pkg/apis/sessions"
	"github.com/ayushbpl10/proxy/pkg/sessions"
	"github.com/ayushbpl10/proxy/providers"
)

//Key cookie
const HashKeyCookie = "12206ca11081508c46342b2e38497011"

type ClientOptions struct {

	ClientID        string
	ClientSecret    string
	ProviderName    string

	// These options allow for other providers besides Google, with
	// potential overrides.
	OIDCIssuerURL     		string
	OIDCJwksURL       		string
	LoginURL          		string
	RedeemURL         		string
	ProfileURL        		string
	ProtectedResource 		string
	ValidateURL       		string
	Scope             		string
	SkipOIDCDiscovery 	    bool
	ApprovalPrompt    	    string


	// internal values that are set after config validation
	provider      			*providers.Provider
	oidcVerifier  			*oidc.IDTokenVerifier
}

// Options holds Configuration Options that can be set by Command Line Flag,
// or Config File
type Options struct {

	// Embed CookieOptions
	options.CookieOptions

	// Embed SessionOptions
	options.SessionOptions

	RedirectURL           string

	Client		          []ClientOptions

	WhitelistDomains    []string

	// Configuration values for logging
	LoggingFilename       string
	LoggingMaxSize        int
	LoggingMaxAge         int
	LoggingMaxBackups     int
	LoggingLocalTime      bool
	LoggingCompress       bool
	StandardLogging       bool
	StandardLoggingFormat string
	RequestLogging        bool
	RequestLoggingFormat  string
	AuthLogging           bool
	AuthLoggingFormat     string

	AcrValues       string
	JWTKey          string
	JWTKeyFile      string
	PubJWKURL       string


	// internal values that are set after config validation
	CompiledRegex []*regexp.Regexp
	sessionStore  sessionsapi.SessionStore
	signatureData *SignatureData
	redirectURL   			*url.URL
}

// SignatureData holds hmacauth signature hash and key
type SignatureData struct {
	hash crypto.Hash
	key  string
}

// NewOptions constructs a new Options with defaulted values
func NewOptions() *Options {

	clients := make([]ClientOptions,0)

	googleClient := ClientOptions{
		ProviderName: 			"google",
		ClientID: 				"492051402277-jjgt15h9nc3p0d550dcbagn9d87f5hqn.apps.googleusercontent.com",
		ClientSecret:			"vQyHZ6IxPdTcIQ8BFHXCpO-W",
		OIDCIssuerURL: 			"https://accounts.google.com",
		ApprovalPrompt:			"force",
		SkipOIDCDiscovery:		false,
		Scope:					"openid email profile",
	}

	if googleClient.OIDCIssuerURL != "" {

		ctx := context.Background()

		// Construct a manual IDTokenVerifier from issuer URL & JWKS URI
		// instead of metadata discovery if we enable -skip-oidc-discovery.
		// In this case we need to make sure the required endpoints for
		// the provider are configured.
		if googleClient.SkipOIDCDiscovery {
			if googleClient.LoginURL == "" {
				panic(errors.New("missing setting: login-url"))
			}
			if googleClient.RedeemURL == "" {
				panic(errors.New("missing setting: redeem-url"))
			}
			if googleClient.OIDCJwksURL == "" {
				panic(errors.New("missing setting: oidc-jwks-url"))
			}
			keySet := oidc.NewRemoteKeySet(ctx, googleClient.OIDCJwksURL)
			googleClient.oidcVerifier = oidc.NewVerifier(googleClient.OIDCIssuerURL, keySet, &oidc.Config{
				ClientID: googleClient.ClientID,
			})
		} else {
			// Configure discoverable provider data.
			provider, err := oidc.NewProvider(ctx, googleClient.OIDCIssuerURL)
			if err != nil {
				panic(err)
			}
			googleClient.oidcVerifier = provider.Verifier(&oidc.Config{
				ClientID: googleClient.ClientID,
			})

			googleClient.LoginURL = provider.Endpoint().AuthURL
			googleClient.RedeemURL = provider.Endpoint().TokenURL

		}
		if googleClient.Scope == "" {
			googleClient.Scope = "openid email profile"
		}
	}

	clients = append(clients, googleClient)

	return &Options{
		CookieOptions: options.CookieOptions{
			CookieName:     "_oauth2_proxy",
			CookieSecret:   HashKeyCookie,
			CookieDomain:   "127.0.0.1",
			CookieSecure:   false,
			CookieHTTPOnly: true,
			CookieExpire:   time.Duration(168) * time.Hour,
			CookieRefresh:  time.Duration(0),
		},
		SessionOptions: options.SessionOptions{
			Type: "cookie",
		},
		Client: 			   clients,
		LoggingFilename:       "",
		LoggingMaxSize:        100,
		LoggingMaxAge:         7,
		LoggingMaxBackups:     0,
		LoggingLocalTime:      true,
		LoggingCompress:       false,
		StandardLogging:       true,
		StandardLoggingFormat: logger.DefaultStandardLoggingFormat,
		RequestLogging:        true,
		RequestLoggingFormat:  logger.DefaultRequestLoggingFormat,
		AuthLogging:           true,
		AuthLoggingFormat:     logger.DefaultAuthLoggingFormat,
		RedirectURL:           "/proxy/auth/callback",
		redirectURL:           parseURL("/proxy/auth/callback", "redirect"),
		WhitelistDomains:      []string{"127.0.0.1:5000","waqt.appointy.com"},
	}
}

func parseURL(toParse string, urltype string) *url.URL {
	parsed, err := url.Parse(toParse)
	if err != nil {
		panic(fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, toParse, err))
	}
	return parsed
}

// Validate checks that required options are set and validates those that they
// are of the correct format
func (o *Options) Validate() error {

	msgs := make([]string, 0)
	if o.CookieSecret == "" {
		panic("missing setting: cookie-secret")
	}

	parseProviderInfo(o)

	var cipher *cookie.Cipher
	if o.CookieRefresh != time.Duration(0) {
		validCookieSecretSize := false
		for _, i := range []int{16, 24, 32} {
			if len(secretBytes(o.CookieSecret)) == i {
				validCookieSecretSize = true
			}
		}
		var decoded bool
		if string(secretBytes(o.CookieSecret)) != o.CookieSecret {
			decoded = true
		}
		if validCookieSecretSize == false {
			var suffix string
			if decoded {
				suffix = fmt.Sprintf(" note: cookie secret was base64 decoded from %q", o.CookieSecret)
			}
			panic(fmt.Sprintf(
				"cookie_secret must be 16, 24, or 32 bytes "+
					"to create an AES cipher when "+
					"pass_access_token == true or "+
					"cookie_refresh != 0, but is %d bytes.%s",
				len(secretBytes(o.CookieSecret)), suffix))
		} else {
			var err error
			cipher, err = cookie.NewCipher(secretBytes(o.CookieSecret))
			if err != nil {
				panic(fmt.Sprintf("cookie-secret error: %v", err))
			}
		}
	}

	o.SessionOptions.Cipher = cipher
	sessionStore, err := sessions.NewSessionStore(&o.SessionOptions, &o.CookieOptions)
	if err != nil {
		msgs = append(msgs, fmt.Sprintf("error initialising session storage: %v", err))
	} else {
		o.sessionStore = sessionStore
	}

	if o.CookieRefresh >= o.CookieExpire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%s) must be less than "+
				"cookie_expire (%s)",
			o.CookieRefresh.String(),
			o.CookieExpire.String()))
	}

	//msgs = parseSignatureKey(o, msgs)
	msgs = validateCookieName(o, msgs)
	//msgs = setupLogger(o, msgs)

	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseProviderInfo(o *Options) {

	for i, c := range o.Client {
		p := &providers.ProviderData{
			ProviderName:   c.ProviderName,
			Scope:          c.Scope,
			ClientID:       c.ClientID,
			ClientSecret:   c.ClientSecret,
			ApprovalPrompt: c.ApprovalPrompt,
		}

		p.LoginURL = parseURL(c.LoginURL, "login")
		p.RedeemURL = parseURL(c.RedeemURL, "redeem")
		p.ProfileURL = parseURL(c.ProfileURL, "profile")
		p.ValidateURL = parseURL(c.ValidateURL, "validate")
		p.ProtectedResource = parseURL(c.ProtectedResource, "resource")

		pInput := providers.ProviderInput{
			ProviderName:c.ProviderName,
			P: p,
		}

		pr := providers.New(pInput)
		o.Client[i].provider = &pr

		switch p := pr.(type) {
		case *providers.OIDCProvider:
			if c.oidcVerifier == nil {
				panic("oidc provider requires an oidc issuer URL")
			} else {
				p.Verifier = c.oidcVerifier
			}
		}
	}
}

//func parseSignatureKey(o *Options, msgs []string) []string {
//	if o.SignatureKey == "" {
//		return msgs
//	}
//
//	components := strings.Split(o.SignatureKey, ":")
//	if len(components) != 2 {
//		return append(msgs, "invalid signature hash:key spec: "+
//			o.SignatureKey)
//	}
//
//	algorithm, secretKey := components[0], components[1]
//	var hash crypto.Hash
//	var err error
//	if hash, err = hmacauth.DigestNameToCryptoHash(algorithm); err != nil {
//		return append(msgs, "unsupported signature hash algorithm: "+
//			o.SignatureKey)
//	}
//	o.signatureData = &SignatureData{hash, secretKey}
//	return msgs
//}

func validateCookieName(o *Options, msgs []string) []string {
	cookie := &http.Cookie{Name: o.CookieName}
	if cookie.String() == "" {
		return append(msgs, fmt.Sprintf("invalid cookie name: %q", o.CookieName))
	}
	return msgs
}

func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}

// secretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func secretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		return []byte(addPadding(string(b)))
	}
	return []byte(secret)
}
//
//func setupLogger(o *Options, msgs []string) []string {
//	// Setup the log file
//	if len(o.LoggingFilename) > 0 {
//		// Validate that the file/dir can be written
//		file, err := os.OpenFile(o.LoggingFilename, os.O_WRONLY|os.O_CREATE, 0666)
//		if err != nil {
//			if os.IsPermission(err) {
//				return append(msgs, "unable to write to log file: "+o.LoggingFilename)
//			}
//		}
//		file.Close()
//
//		logger.Printf("Redirecting logging to file: %s", o.LoggingFilename)
//
//		logWriter := &lumberjack.Logger{
//			Filename:   o.LoggingFilename,
//			MaxSize:    o.LoggingMaxSize, // megabytes
//			MaxAge:     o.LoggingMaxAge,  // days
//			MaxBackups: o.LoggingMaxBackups,
//			LocalTime:  o.LoggingLocalTime,
//			Compress:   o.LoggingCompress,
//		}
//
//		logger.SetOutput(logWriter)
//	}
//
//	// Supply a sanity warning to the logger if all logging is disabled
//	if !o.StandardLogging && !o.AuthLogging && !o.RequestLogging {
//		logger.Print("Warning: Logging disabled. No further logs will be shown.")
//	}
//
//	// Pass configuration values to the standard logger
//	logger.SetStandardEnabled(o.StandardLogging)
//	logger.SetAuthEnabled(o.AuthLogging)
//	logger.SetReqEnabled(o.RequestLogging)
//	logger.SetStandardTemplate(o.StandardLoggingFormat)
//	logger.SetAuthTemplate(o.AuthLoggingFormat)
//	logger.SetReqTemplate(o.RequestLoggingFormat)
//
//	if !o.LoggingLocalTime {
//		logger.SetFlags(logger.Flags() | logger.LUTC)
//	}
//
//	return msgs
//}