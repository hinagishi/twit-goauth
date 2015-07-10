/*
Package twitgoauth implements a library for authenticate Twitter with Oauth.
*/
package twitgoauth

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A Token struct for consumer, request, and access token.
type Token struct {
	Token  string
	Secret string
}

const (
	requestTokenURL = "https://api.twitter.com/oauth/request_token"
	accessTokenURL  = "https://api.twitter.com/oauth/access_token"
	authorizeURL    = "http://twitter.com/oauth/authorize?oauth_token="
)

// ReadTokens reads consumer and access tokens from a file.
func ReadTokens(file string) (*Token, *Token, string, error) {
	fp, err := os.Open(file)
	if err != nil {
		return nil, nil, "", err
	}
	defer fp.Close()

	consumer := new(Token)
	access := new(Token)
	var name string
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		key := strings.Split(scanner.Text(), ":")
		if len(key) < 2 {
			continue
		}
		if strings.Trim(strings.Trim(key[0], " "), " ") == "consumer_key" {
			consumer.Token = strings.Trim(key[1], " ")
		} else if strings.Trim(key[0], " ") == "consumer_secret" {
			consumer.Secret = strings.Trim(key[1], " ")
		} else if strings.Trim(key[0], " ") == "access_token" {
			access.Token = strings.Trim(key[1], " ")
		} else if strings.Trim(key[0], " ") == "access_secret" {
			access.Secret = strings.Trim(key[1], " ")
		} else if strings.Trim(key[0], " ") == "screen_name" {
			name = strings.Trim(key[1], " ")
		}
	}
	err = scanner.Err()
	if err != nil {
		return nil, nil, "", err
	}

	if consumer.Token == "" || consumer.Secret == "" {
		fmt.Fprintln(os.Stderr, "Invalid file format.")
		return nil, nil, "", err
	}
	return consumer, access, name, err
}

func random(length int) string {
	const base = 36
	size := big.NewInt(base)
	n := make([]byte, length)
	for i := range n {
		c, _ := rand.Int(rand.Reader, size)
		n[i] = strconv.FormatInt(c.Int64(), base)[0]
	}
	return string(n)
}

func getTimestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func getToken(method string, url string, query string) (string, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(os.Stderr, query)
	req.URL.RawQuery = query
	req.Header.Add("Authorize", "Oauth")
	client := new(http.Client)
	resp, err := client.Do(req)
	defer resp.Body.Close()

	fmt.Fprintln(os.Stderr, resp.StatusCode)
	if resp.StatusCode != 200 {
		return "", err
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	fmt.Println(string(buf))
	return string(buf), nil
}

// CreateOauthTemplate creates a map includes items for oauth.
func CreateOauthTemplate(consumer *Token) map[string]string {
	config := make(map[string]string)
	config["oauth_consumer_key"] = consumer.Token
	config["oauth_signature_method"] = "HMAC-SHA1"
	config["oauth_version"] = "1.0"
	return config
}

// GetRequestToken retrieves a request token from Twitter API server.
func GetRequestToken(consumer *Token, config map[string]string) (*Token, error) {
	config["oauth_nonce"] = random(32)
	config["oauth_timestamp"] = getTimestamp()

	param1 := "GET&" + url.QueryEscape(requestTokenURL) + "&"
	param2 := CreateQuery(config)
	param3 := url.QueryEscape(consumer.Secret) + "&"
	param1 += url.QueryEscape(param2)

	hash := hmac.New(sha1.New, []byte(param3))
	hash.Write([]byte(param1))
	sig := url.QueryEscape(base64.StdEncoding.EncodeToString(hash.Sum(nil)))
	query := param2 + "&oauth_signature=" + sig
	result, err := getToken("GET", requestTokenURL, query)
	fmt.Println(config)

	if err != nil {
		return nil, err
	}
	reqToken := new(Token)
	reqToken.Token = strings.Split(strings.Split(result, "&")[0], "=")[1]
	reqToken.Secret = strings.Split(strings.Split(result, "&")[1], "=")[1]
	return reqToken, nil
}

// GetPinURL returns a URL to get PIN code.
func GetPinURL(reqtoken *Token) string {
	return authorizeURL + reqtoken.Token
}

// CreateQuery makes a query string
func CreateQuery(config map[string]string) string {
	config["oauth_nonce"] = random(32)
	config["oauth_timestamp"] = getTimestamp()
	index := make([]string, len(config))
	n := 0
	for i := range config {
		index[n] = i
		n++
	}
	sort.Strings(index)
	var query string
	for c := range index {
		if query != "" {
			query += "&"
		}
		query += index[c] + "=" + config[index[c]]
	}
	return query
}

// GetAccessToken retrieves access token and secret.
func GetAccessToken(consumer *Token, token *Token, config map[string]string) (*Token, string, error) {

	param1 := "GET&" + url.QueryEscape(accessTokenURL) + "&"
	config["oauth_nonce"] = random(32)
	config["oauth_timestamp"] = getTimestamp()
	config["oauth_token"] = token.Token
	param2 := CreateQuery(config)
	param3 := url.QueryEscape(consumer.Secret) + "&"
	param3 += url.QueryEscape(token.Secret)
	param1 += url.QueryEscape(param2)

	hash := hmac.New(sha1.New, []byte(param3))
	hash.Write([]byte(param1))
	sig := url.QueryEscape(base64.StdEncoding.EncodeToString(hash.Sum(nil)))
	query := param2 + "&oauth_signature=" + sig
	result, err := getToken("GET", accessTokenURL, query)
	if err != nil {
		return nil, "", err
	}
	access := new(Token)
	access.Token = strings.Split(strings.Split(result, "&")[0], "=")[1]
	access.Secret = strings.Split(strings.Split(result, "&")[1], "=")[1]
	name := strings.Split(strings.Split(result, "&")[3], "=")[1]
	return access, name, nil
}

// SaveTokens stores consumer keys, access tokens and screen_name to a file.
func SaveTokens(filename string, consumer *Token, access *Token, name string) {
	output := "consumer_key:" + consumer.Token
	output += "\nconsumer_secret:" + consumer.Secret
	output += "\naccess_token:" + access.Token
	output += "\naccess_secret:" + access.Secret
	output += "\nscreen_name:" + name
	ioutil.WriteFile(filename, []byte(output), os.ModePerm)
}
