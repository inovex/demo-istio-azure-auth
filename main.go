package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type OauthFlowType string

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

const (
	ImplicitGrantFlow OauthFlowType = "implicit"
	AuthCodeGrant     OauthFlowType = "auth_code"
)

var (
	listenAddress = os.Getenv("LISTEN_ADDRESS")
	oauthFlow     = OauthFlowType(os.Getenv("OAUTH_FLOW_TYPE"))
	tenantId      = os.Getenv("TENANT_ID")
	clientId      = os.Getenv("CLIENT_ID")
	redirectUri   = os.Getenv("REDIRECT_URI")
	clientSecret  = os.Getenv("CLIENT_SECRET")
	requestScope  = os.Getenv("REQUEST_SCOPE")
)

func init() {
	if len(listenAddress) <= 0 {
		listenAddress = ":8080"
	}
	if len(oauthFlow) <= 0 {
		oauthFlow = ImplicitGrantFlow
	}
}

func main() {
	if oauthFlow == AuthCodeGrant && len(tenantId) <= 0 || len(clientId) <= 0 {
		log.Fatal(fmt.Errorf("both TENANT_ID and CLIENT_ID are required for OAUTH_FLOW_TYPE %s", AuthCodeGrant))
	}
	if oauthFlow == AuthCodeGrant && len(redirectUri) <= 0 {
		log.Fatal(fmt.Errorf("REDIRECT_URI is required when using OAUTH_FLOW_TYPE %s", AuthCodeGrant))
	}
	if oauthFlow == AuthCodeGrant && len(clientSecret) <= 0 {
		log.Fatal(fmt.Errorf("CLIENT_SECRET is required when using OAUTH_FLOW_TYPE %s", AuthCodeGrant))
	}
	if oauthFlow == AuthCodeGrant && len(requestScope) <= 0 {
		log.Fatal(fmt.Errorf("REQUEST_SCOPE is required when using OAUTH_FLOW_TYPE %s", AuthCodeGrant))
	}
	http.HandleFunc("/", HelloServer)
	http.ListenAndServe(listenAddress, nil)
}

func HelloServer(w http.ResponseWriter, r *http.Request) {
	formParams, err := getFormParamsFromBody(r.Body)
	if err != nil {
		handleRequestError(errors.Wrap(err, "error decoding body of request"), w)
		return
	}
	log.Println("formParams: ")
	for key, value := range formParams {
		log.Println(key, value)
	}
	log.Println("formParams END")
	if oauthFlow == AuthCodeGrant {
		code, ok := formParams["code"]
		if !ok || len(code) > 1 {
			log.Fatal(fmt.Errorf("params %v must contain exactly one param code", formParams))
		}
		resp, err := requestAuthToken(code[0])
		if err != nil {
			handleRequestError(errors.Wrap(err, "failed to retrieve auth token"), w)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			handleRequestError(fmt.Errorf("unsuccesful token request, resp: %+v", resp), w)
			log.Println(getFormParamsFromBody(resp.Body))
			return
		}
		respFormParams, err := getFormParamsFromBody(resp.Body)
		if err != nil {
			handleRequestError(errors.Wrap(err, "error decoding body of token-retrieve request"), w)
			return
		}

		accessToken, ok := respFormParams["access_token"]
		if !ok {
			// for some reason we get the whole query as first key in the parsed params
			// we therefore parse this key
			for key, _ := range respFormParams {
				log.Println("found key ", key)
				var tokenResponse TokenResponse
				err := json.Unmarshal([]byte(key), &tokenResponse)
				if err != nil {
					log.Println("key could not be parsed as json: ", err)
					continue
				}
				accessToken = []string{tokenResponse.AccessToken}
				ok = true
			}
		}
		if !ok {
			handleRequestError(fmt.Errorf("params %v of token request do not contain param access_token", respFormParams), w)
			println(fmt.Sprintf("raw response: %+v", resp))
			return
		}
		SetAccessTokenCookie(accessToken[0], w, r)
	} else if oauthFlow == ImplicitGrantFlow {
		accessToken, ok := formParams["access_token"]
		if !ok {
			handleRequestError(fmt.Errorf("params %v do not contain param access_token", formParams), w)
			return
		}
		SetAccessTokenCookie(accessToken[0], w, r)
	} else {
		handleRequestError(fmt.Errorf("unknown OAUTH_FLOW_TYPE %s, please use %s of %s", oauthFlow, ImplicitGrantFlow, AuthCodeGrant), w)
	}
}

func requestAuthToken(code string) (*http.Response, error) {
	postBodyData := url.Values{}
	postBodyData.Set("client_id", clientId)
	postBodyData.Set("grant_type", "authorization_code")
	postBodyData.Set("scope", requestScope)
	postBodyData.Set("code", code)
	postBodyData.Set("redirect_uri", redirectUri)
	postBodyData.Set("client_secret", clientSecret)
	postReqUri := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId)
	resp, err := http.Post(postReqUri, "application/x-www-form-urlencoded", strings.NewReader(postBodyData.Encode()))
	return resp, err
}

func handleRequestError(err error, w http.ResponseWriter) {
	log.Println(err)
	w.WriteHeader(http.StatusInternalServerError)
}

func getFormParamsFromBody(body io.ReadCloser) (url.Values, error) {
	if body == nil {
		return nil, errors.New("body was empty")
	}
	bodyBytes, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, err
	}
	formParams, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return nil, err
	}
	return formParams, nil
}

func SetAccessTokenCookie(accessToken string, w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  time.Now().Add(5 * time.Minute),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
	redirect_uri := r.URL.Query().Get("redirect_uri")
	http.Redirect(w, r, redirect_uri, http.StatusFound)
}
