package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"errors"
	"github.com/ayushbpl10/proxy/cookie"
	"github.com/ayushbpl10/proxy/logger"
	sessionsapi "github.com/ayushbpl10/proxy/pkg/apis/sessions"
	"github.com/ayushbpl10/proxy/providers"
)

const (
	// SignatureHeader is the name of the request header containing the GAP Signature
	// Part of hmacauth
	SignatureHeader = "GAP-Signature"

	httpScheme  = "http"
	httpsScheme = "https"

	applicationJSON = "application/json"
)

// OAuthProxy is the main authentication proxy
type OAuthProxy struct {
	CookieSeed     string
	CookieName     string
	CSRFCookieName string
	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieExpire   time.Duration
	CookieRefresh  time.Duration

	AuthOnlyPath      string

	redirectURL         *url.URL // the url to receive requests at
	whitelistDomains    []string
	Provider            []providers.Provider
	sessionStore        sessionsapi.SessionStore
	ProxyPrefix         string
}

// NewOAuthProxy creates a new instance of OOuthProxy from the options provided
func NewOAuthProxy(opts *Options) *OAuthProxy {

	redirectURL := opts.redirectURL

	//logger.Printf("OAuthProxy configured for %s Client ID: %s", opts.provider.Data().ProviderName, opts.ClientID)
	refresh := "disabled"
	if opts.CookieRefresh != time.Duration(0) {
		refresh = fmt.Sprintf("after %s", opts.CookieRefresh)
	}

	logger.Printf("Cookie settings: name:%s secure(https):%v httponly:%v expiry:%s domain:%s path:%s refresh:%s", opts.CookieName, opts.CookieSecure, opts.CookieHTTPOnly, opts.CookieExpire, opts.CookieDomain, opts.CookiePath, refresh)

	provs := make([]providers.Provider,0)

	for _, c := range opts.Client {
		provs = append(provs, *c.provider)
	}

	return &OAuthProxy{
		CookieName:     opts.CookieName,
		CSRFCookieName: fmt.Sprintf("%v_%v", opts.CookieName, "csrf"),
		CookieSeed:     opts.CookieSecret,
		CookieDomain:   opts.CookieDomain,
		CookiePath:     opts.CookiePath,
		CookieSecure:   opts.CookieSecure,
		CookieHTTPOnly: opts.CookieHTTPOnly,
		CookieExpire:   opts.CookieExpire,
		CookieRefresh:  opts.CookieRefresh,

		Provider:           provs,
		sessionStore:       opts.sessionStore,
		redirectURL:        redirectURL,
		whitelistDomains:   opts.WhitelistDomains,
	}
}


// GetRedirectURI returns the redirectURL that the upstream OAuth Provider will
// redirect clients to once authenticated
func (p *OAuthProxy) GetRedirectURI(host string) string {
	// default to the request Host if not set
	if p.redirectURL.Host != "" {
		return p.redirectURL.String()
	}
	var u url.URL
	u = *p.redirectURL
	if u.Scheme == "" {
		if p.CookieSecure {
			u.Scheme = httpsScheme
		} else {
			u.Scheme = httpScheme
		}
	}
	u.Host = host
	return u.String()
}

func (p *OAuthProxy) redeemCode(host, code string, pr providers.Provider) (s *sessionsapi.SessionState, err error) {
	if code == "" {
		return nil, errors.New("missing code")
	}
	redirectURI := p.GetRedirectURI(host)

	s, err = pr.Redeem(redirectURI, code)
	if err != nil {
		return
	}

	if s.Email == "" {
		s.Email, err = pr.GetEmailAddress(s)
	}

	if s.User == "" {
		s.User, err = pr.GetUserName(s)
		if err != nil && err.Error() == "not implemented" {
			err = nil
		}
	}

	return
}

// MakeCSRFCookie creates a cookie for CSRF
func (p *OAuthProxy) MakeCSRFCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return p.makeCookie(req, p.CSRFCookieName, value, expiration, now)
}

func (p *OAuthProxy) makeCookie(req *http.Request, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
	if p.CookieDomain != "" {
		domain := req.Host
		if h, _, err := net.SplitHostPort(domain); err == nil {
			domain = h
		}
		if !strings.HasSuffix(domain, p.CookieDomain) {
			logger.Printf("Warning: request host is %q but using configured cookie domain of %q", domain, p.CookieDomain)
		}
	}

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     p.CookiePath,
		Domain:   p.CookieDomain,
		HttpOnly: p.CookieHTTPOnly,
		Secure:   p.CookieSecure,
		Expires:  now.Add(expiration),
	}
}

// ClearCSRFCookie creates a cookie to unset the CSRF cookie stored in the user's
// session
func (p *OAuthProxy) ClearCSRFCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, p.MakeCSRFCookie(req, "", time.Hour*-1, time.Now()))
}

// SetCSRFCookie adds a CSRF cookie to the response
func (p *OAuthProxy) SetCSRFCookie(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, p.MakeCSRFCookie(req, val, p.CookieExpire, time.Now()))
}

// ClearSessionCookie creates a cookie to unset the user's authentication cookie
// stored in the user's session
func (p *OAuthProxy) ClearSessionCookie(rw http.ResponseWriter, req *http.Request) error {
	return p.sessionStore.Clear(rw, req)
}

// LoadCookiedSession reads the user's authentication details from the request
func (p *OAuthProxy) LoadCookiedSession(req *http.Request) (*sessionsapi.SessionState, error) {
	return p.sessionStore.Load(req)
}

// SaveSession creates a new session cookie value and sets this on the response
func (p *OAuthProxy) SaveSession(rw http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) error {
	return p.sessionStore.Save(rw, req, s)
}

// GetRedirect reads the query parameter to get the URL to redirect clients to
// once authenticated with the OAuthProxy
func (p *OAuthProxy) GetRedirect(req *http.Request) (redirect string, err error) {
	//err = req.ParseForm()
	//if err != nil {
	//	return
	//}

	redirect = req.URL.Query().Get("rd")
	if !p.IsValidRedirect(redirect) {
		redirect = req.URL.Path
		if strings.HasPrefix(redirect, p.ProxyPrefix) {
			redirect = "/"
		}
	}

	return
}

// IsValidRedirect checks whether the redirect URL is whitelisted
func (p *OAuthProxy) IsValidRedirect(redirect string) bool {
	switch {
	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//"):
		return true
	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
		redirectURL, err := url.Parse(redirect)
		if err != nil {
			return false
		}
		for _, domain := range p.whitelistDomains {
			if (redirectURL.Host == domain) || (strings.HasPrefix(domain, ".") && strings.HasSuffix(redirectURL.Host, domain)) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func getRemoteAddr(req *http.Request) (s string) {
	s = req.RemoteAddr
	if req.Header.Get("X-Real-IP") != "" {
		s += fmt.Sprintf(" (%q)", req.Header.Get("X-Real-IP"))
	}
	return
}

// SignOut sends a response to clear the authentication cookie
func (p *OAuthProxy) SignOut(rw http.ResponseWriter, req *http.Request) {
	p.ClearSessionCookie(rw, req)
	http.Redirect(rw, req, "/", 302)
}

// OAuthStart starts the OAuth2 authentication flow
func (p *OAuthProxy) OAuthStart(rw http.ResponseWriter, req *http.Request, pro providers.Provider) {
	nonce, err := cookie.Nonce()
	if err != nil {
		logger.Printf("Error obtaining nonce: %s", err.Error())
		http.Error(rw,"Something went wrong", http.StatusInternalServerError)
		return
	}

	p.SetCSRFCookie(rw, req, nonce)

	redirect, err := p.GetRedirect(req)
	if err != nil {
		logger.Printf("Error obtaining redirect: %s", err.Error())
		http.Error(rw,"Something went wrong", http.StatusInternalServerError)
		return
	}

	redirectURI := p.GetRedirectURI(req.Host)

	prName := req.URL.Query().Get("provider")
	if prName == "" {
		http.Error(rw, "No Provider specified", http.StatusBadRequest)
		return
	}

	url := pro.GetLoginURL(redirectURI, fmt.Sprintf("%v:%v:%v", nonce, redirect, prName))
	if url == "" {
		http.Error(rw, "No Login URL exists for this provider", http.StatusBadRequest)
		return
	}

	http.Redirect(rw, req, url, 302)
}

// OAuthCallback is the OAuth2 authentication flow callback that finishes the
// OAuth2 authentication flow
func (p *OAuthProxy) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	remoteAddr := getRemoteAddr(req)

	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		logger.Printf("Error while parsing OAuth2 callback: %s" + err.Error())
		http.Error(rw,"Something went wrong", http.StatusInternalServerError)
		return
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		logger.Printf("Error while parsing OAuth2 callback: %s ", errorString)
		http.Error(rw,"Something went wrong", http.StatusForbidden)
		return
	}

	s := strings.SplitN(req.Form.Get("state"), ":", 3)
	if len(s) != 3 {
		logger.Printf("Error while parsing OAuth2 state: invalid length")
		http.Error(rw,"Something went wrong", http.StatusInternalServerError)
		return
	}

	nonce := s[0]
	redirect := s[1]
	prov := s[2]

	pr,err := p.GetProviderByName(prov)
	if err != nil {
		logger.Printf("Provider Not Found: %s ", errorString)
		http.Error(rw,"Provider Not Found", http.StatusForbidden)
		return
	}

	session, err := p.redeemCode(req.Host, req.Form.Get("code"), pr)
	if err != nil {
		logger.Printf("Error redeeming code during OAuth2 callback: %s ", err.Error())
		http.Error(rw,"Something went wrong", http.StatusInternalServerError)
		return
	}

	c, err := req.Cookie(p.CSRFCookieName)
	if err != nil {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: unable too obtain CSRF cookie")
		http.Error(rw,"Something went wrong", http.StatusForbidden)
		return
	}
	p.ClearCSRFCookie(rw, req)

	if c.Value != nonce {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: csrf token mismatch, potential attack")
		http.Error(rw,"Something went wrong", http.StatusForbidden)
		return
	}

	if !p.IsValidRedirect(redirect) {
		redirect = "/"
	}

	provider,err := p.GetProviderByName(prov)
	if err != nil{
		http.Error(rw,"No such provider", http.StatusForbidden)
		return
	}

	if provider == nil || provider.Data() == nil || provider.Data().ProviderName == "" {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Provider not found: %s", prov)
	}

	// set cookie, or deny

	logger.PrintAuthf(session.Email, req, logger.AuthSuccess, "Authenticated via OAuth2: %s", session)
	err = p.SaveSession(rw, req, session)
	if err != nil {
		logger.Printf("%s %s", remoteAddr, err)
		http.Error(rw,"Internal Error", http.StatusInternalServerError)
		return
	}

	return
}

// AuthenticateOnly checks whether the user is currently logged in
func (p *OAuthProxy) AuthenticateOnly(rw http.ResponseWriter, req *http.Request, prov providers.Provider) {
	status := p.Authenticate(rw, req, prov)
	if status == http.StatusAccepted {
		rw.WriteHeader(http.StatusAccepted)
	} else {
		http.Error(rw, "unauthorized request", http.StatusUnauthorized)
	}
}

func (p *OAuthProxy) GetProviderByName(providerName string) (providers.Provider, error) {

	for _, p := range p.Provider {
		if strings.ToLower(p.Data().ProviderName) != strings.ToLower(providerName) {
			continue
		}

		return p, nil
	}

	return nil, errors.New("No provider found")
}
// Proxy proxies the user request if the user is authenticated else it prompts
// them to authenticate
//func (p *OAuthProxy) Proxy(rw http.ResponseWriter, req *http.Request) {
//	status := p.Authenticate(rw, req)
//	if status == http.StatusInternalServerError {
//		p.ErrorPage(rw, http.StatusInternalServerError,
//			"Internal Error", "Internal Error")
//	} else if status == http.StatusForbidden {
//		if p.SkipProviderButton {
//			p.OAuthStart(rw, req)
//		} else {
//			logger.Printf("Error obtaining sign in: NO sign in page")
//			return
//			//p.SignInPage(rw, req, http.StatusForbidden)
//		}
//	} else if status == http.StatusUnauthorized {
//		p.ErrorJSON(rw, status)
//	} else {
//		p.serveMux.ServeHTTP(rw, req)
//	}
//}

// Authenticate checks whether a user is authenticated
func (p *OAuthProxy) Authenticate(rw http.ResponseWriter, req *http.Request, pro providers.Provider) int {
	var saveSession, clearSession, revalidated bool
	remoteAddr := getRemoteAddr(req)

	session, err := p.LoadCookiedSession(req)
	if err != nil {
		logger.Printf("Error loading cookied session: %s", err)
	}
	if session != nil && session.Age() > p.CookieRefresh && p.CookieRefresh != time.Duration(0) {
		logger.Printf("Refreshing %s old session cookie for %s (refresh after %s)", session.Age(), session, p.CookieRefresh)
		saveSession = true
	}

	var ok bool
	if ok, err = pro.RefreshSessionIfNeeded(session); err != nil {
		logger.Printf("%s removing session. error refreshing access token %s %s", remoteAddr, err, session)
		clearSession = true
		session = nil
	} else if ok {
		saveSession = true
		revalidated = true
	}

	if session != nil && session.IsExpired() {
		logger.Printf("Removing session: token expired %s", session)
		session = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && !revalidated && session != nil && session.AccessToken != "" {
		if !pro.ValidateSessionState(session) {
			logger.Printf("Removing session: error validating %s", session)
			saveSession = false
			session = nil
			clearSession = true
		}
	}

	if session != nil && session.Email != "" {
		logger.Printf(session.Email, req, logger.AuthFailure, "Invalid authentication via session: removing session %s", session)
		session = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && session != nil {
		err = p.SaveSession(rw, req, session)
		if err != nil {
			logger.PrintAuthf(session.Email, req, logger.AuthError, "Save session error %s", err)
			return http.StatusInternalServerError
		}
	}

	if clearSession {
		p.ClearSessionCookie(rw, req)
	}

	if session == nil {
		session, err = p.CheckBasicAuth(req)
		if err != nil {
			logger.Printf("Error during basic auth validation: %s", err)
		}
	}

	if session == nil {
		// Check if is an ajax request and return unauthorized to avoid a redirect
		// to the login page
		if p.isAjax(req) {
			return http.StatusUnauthorized
		}
		return http.StatusForbidden
	}

	return http.StatusAccepted
}

// CheckBasicAuth checks the requests Authorization header for basic auth
// credentials and authenticates these against the proxies HtpasswdFile
func (p *OAuthProxy) CheckBasicAuth(req *http.Request) (*sessionsapi.SessionState, error) {
	//if p.HtpasswdFile == nil {
	//	return nil, nil
	//}
	//auth := req.Header.Get("Authorization")
	//if auth == "" {
	//	return nil, nil
	//}
	//s := strings.SplitN(auth, " ", 2)
	//if len(s) != 2 || s[0] != "Basic" {
	//	return nil, fmt.Errorf("invalid Authorization header %s", req.Header.Get("Authorization"))
	//}
	//b, err := b64.StdEncoding.DecodeString(s[1])
	//if err != nil {
	//	return nil, err
	//}
	//pair := strings.SplitN(string(b), ":", 2)
	//if len(pair) != 2 {
	//	return nil, fmt.Errorf("invalid format %s", b)
	//}
	//if p.HtpasswdFile.Validate(pair[0], pair[1]) {
	//	logger.PrintAuthf(pair[0], req, logger.AuthSuccess, "Authenticated via basic auth and HTpasswd File")
	//	return &sessionsapi.SessionState{User: pair[0]}, nil
	//}
	//logger.PrintAuthf(pair[0], req, logger.AuthFailure, "Invalid authentication via basic auth: not in Htpasswd File")
	return nil, nil
}

// isAjax checks if a request is an ajax request
func (p *OAuthProxy) isAjax(req *http.Request) bool {
	acceptValues, ok := req.Header["accept"]
	if !ok {
		acceptValues = req.Header["Accept"]
	}
	const ajaxReq = applicationJSON
	for _, v := range acceptValues {
		if v == ajaxReq {
			return true
		}
	}
	return false
}

// ErrorJSON returns the error code witht an application/json mime type
func (p *OAuthProxy) ErrorJSON(rw http.ResponseWriter, code int) {
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(code)
}