package sessions_test

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ayushbpl10/oauth2_proxy/cookie"
	"github.com/ayushbpl10/oauth2_proxy/pkg/apis/options"
	sessionsapi "github.com/ayushbpl10/oauth2_proxy/pkg/apis/sessions"
	"github.com/ayushbpl10/oauth2_proxy/pkg/cookies"
	"github.com/ayushbpl10/oauth2_proxy/pkg/sessions"
	sessionscookie "github.com/ayushbpl10/oauth2_proxy/pkg/sessions/cookie"
	"github.com/ayushbpl10/oauth2_proxy/pkg/sessions/utils"
)

func TestSessionStore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SessionStore")
}

var _ = Describe("NewSessionStore", func() {
	var opts *options.SessionOptions
	var cookieOpts *options.CookieOptions

	var request *http.Request
	var response *httptest.ResponseRecorder
	var session *sessionsapi.SessionState
	var ss sessionsapi.SessionStore

	CheckCookieOptions := func() {
		Context("the cookies returned", func() {
			var cookies []*http.Cookie
			BeforeEach(func() {
				cookies = response.Result().Cookies()
			})

			It("have the correct name set", func() {
				if len(cookies) == 1 {
					Expect(cookies[0].Name).To(Equal(cookieOpts.CookieName))
				} else {
					for _, cookie := range cookies {
						Expect(cookie.Name).To(ContainSubstring(cookieOpts.CookieName))
					}
				}
			})

			It("have the correct path set", func() {
				for _, cookie := range cookies {
					Expect(cookie.Path).To(Equal(cookieOpts.CookiePath))
				}
			})

			It("have the correct domain set", func() {
				for _, cookie := range cookies {
					Expect(cookie.Domain).To(Equal(cookieOpts.CookieDomain))
				}
			})

			It("have the correct HTTPOnly set", func() {
				for _, cookie := range cookies {
					Expect(cookie.HttpOnly).To(Equal(cookieOpts.CookieHTTPOnly))
				}
			})

			It("have the correct secure set", func() {
				for _, cookie := range cookies {
					Expect(cookie.Secure).To(Equal(cookieOpts.CookieSecure))
				}
			})

			It("have a signature timestamp matching session.CreatedAt", func() {
				for _, cookie := range cookies {
					if cookie.Value != "" {
						parts := strings.Split(cookie.Value, "|")
						Expect(parts).To(HaveLen(3))
						Expect(parts[1]).To(Equal(strconv.Itoa(int(session.CreatedAt.Unix()))))
					}
				}
			})

		})
	}

	SessionStoreInterfaceTests := func() {
		Context("when Save is called", func() {
			BeforeEach(func() {
				err := ss.Save(response, request, session)
				Expect(err).ToNot(HaveOccurred())
			})

			It("sets a `set-cookie` header in the response", func() {
				Expect(response.Header().Get("set-cookie")).ToNot(BeEmpty())
			})

			It("Ensures the session CreatedAt is not zero", func() {
				Expect(session.CreatedAt.IsZero()).To(BeFalse())
			})

			CheckCookieOptions()
		})

		Context("when Clear is called", func() {
			BeforeEach(func() {
				cookie := cookies.MakeCookie(request,
					cookieOpts.CookieName,
					"foo",
					cookieOpts.CookiePath,
					cookieOpts.CookieDomain,
					cookieOpts.CookieHTTPOnly,
					cookieOpts.CookieSecure,
					cookieOpts.CookieExpire,
					time.Now(),
				)
				request.AddCookie(cookie)
				err := ss.Clear(response, request)
				Expect(err).ToNot(HaveOccurred())
			})

			It("sets a `set-cookie` header in the response", func() {
				Expect(response.Header().Get("Set-Cookie")).ToNot(BeEmpty())
			})

			CheckCookieOptions()
		})

		Context("when Load is called", func() {
			var loadedSession *sessionsapi.SessionState
			BeforeEach(func() {
				req := httptest.NewRequest("GET", "http://example.com/", nil)
				resp := httptest.NewRecorder()
				err := ss.Save(resp, req, session)
				Expect(err).ToNot(HaveOccurred())

				for _, cookie := range resp.Result().Cookies() {
					request.AddCookie(cookie)
				}
				loadedSession, err = ss.Load(request)
				Expect(err).ToNot(HaveOccurred())
			})

			It("loads a session equal to the original session", func() {
				if cookieOpts.CookieSecret == "" {
					// Only Email and User stored in session when encrypted
					Expect(loadedSession.Email).To(Equal(session.Email))
					Expect(loadedSession.User).To(Equal(session.User))
				} else {
					// All fields stored in session if encrypted

					// Can't compare time.Time using Equal() so remove ExpiresOn from sessions
					l := *loadedSession
					l.CreatedAt = time.Time{}
					l.ExpiresOn = time.Time{}
					s := *session
					s.CreatedAt = time.Time{}
					s.ExpiresOn = time.Time{}
					Expect(l).To(Equal(s))

					// Compare time.Time separately
					Expect(loadedSession.CreatedAt.Equal(session.CreatedAt)).To(BeTrue())
					Expect(loadedSession.ExpiresOn.Equal(session.ExpiresOn)).To(BeTrue())
				}
			})
		})
	}

	RunSessionTests := func() {
		Context("with default options", func() {
			BeforeEach(func() {
				var err error
				ss, err = sessions.NewSessionStore(opts, cookieOpts)
				Expect(err).ToNot(HaveOccurred())
			})

			SessionStoreInterfaceTests()
		})

		Context("with non-default options", func() {
			BeforeEach(func() {
				cookieOpts = &options.CookieOptions{
					CookieName:     "_cookie_name",
					CookiePath:     "/path",
					CookieExpire:   time.Duration(72) * time.Hour,
					CookieRefresh:  time.Duration(3600),
					CookieSecure:   false,
					CookieHTTPOnly: false,
					CookieDomain:   "example.com",
				}

				var err error
				ss, err = sessions.NewSessionStore(opts, cookieOpts)
				Expect(err).ToNot(HaveOccurred())
			})

			SessionStoreInterfaceTests()
		})

		Context("with a cipher", func() {
			BeforeEach(func() {
				secret := make([]byte, 32)
				_, err := rand.Read(secret)
				Expect(err).ToNot(HaveOccurred())
				cookieOpts.CookieSecret = base64.URLEncoding.EncodeToString(secret)
				cipher, err := cookie.NewCipher(utils.SecretBytes(cookieOpts.CookieSecret))
				Expect(err).ToNot(HaveOccurred())
				Expect(cipher).ToNot(BeNil())
				opts.Cipher = cipher

				ss, err = sessions.NewSessionStore(opts, cookieOpts)
				Expect(err).ToNot(HaveOccurred())
			})

			SessionStoreInterfaceTests()
		})
	}

	BeforeEach(func() {
		ss = nil
		opts = &options.SessionOptions{}

		// Set default options in CookieOptions
		cookieOpts = &options.CookieOptions{
			CookieName:     "_oauth2_proxy",
			CookiePath:     "/",
			CookieExpire:   time.Duration(168) * time.Hour,
			CookieRefresh:  time.Duration(0),
			CookieSecure:   true,
			CookieHTTPOnly: true,
		}

		session = &sessionsapi.SessionState{
			AccessToken:  "AccessToken",
			IDToken:      "IDToken",
			ExpiresOn:    time.Now().Add(1 * time.Hour),
			RefreshToken: "RefreshToken",
			Email:        "john.doe@example.com",
			User:         "john.doe",
		}

		request = httptest.NewRequest("GET", "http://example.com/", nil)
		response = httptest.NewRecorder()
	})

	Context("with type 'cookie'", func() {
		BeforeEach(func() {
			opts.Type = options.CookieSessionStoreType
		})

		It("creates a cookie.SessionStore", func() {
			ss, err := sessions.NewSessionStore(opts, cookieOpts)
			Expect(err).NotTo(HaveOccurred())
			Expect(ss).To(BeAssignableToTypeOf(&sessionscookie.SessionStore{}))
		})

		Context("the cookie.SessionStore", func() {
			RunSessionTests()
		})
	})

	Context("with an invalid type", func() {
		BeforeEach(func() {
			opts.Type = "invalid-type"
		})

		It("returns an error", func() {
			ss, err := sessions.NewSessionStore(opts, cookieOpts)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("unknown session store type 'invalid-type'"))
			Expect(ss).To(BeNil())
		})
	})
})
