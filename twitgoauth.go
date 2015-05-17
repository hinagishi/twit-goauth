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
	"strconv"
	"strings"
	"time"
)

type Token struct {
	Token  string
	Secret string
}

const (
	request_token_url = "https://api.twitter.com/oauth/request_token"
	access_token_url  = "https://api.twitter.com/oauth/access_token"
	authorize_url     = "http://twitter.com/oauth/authorize?oauth_token="
)

/*
 * read consumer and access tokens from file
 * @param filename
 * @return ConsumerKeys and AccessTokens
 */
func ReadTokens(file string) (*Token, *Token, error) {
	fp, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	defer fp.Close()

	consumer := new(Token)
	access := new(Token)
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		key := strings.Split(scanner.Text(), ":")
		if len(key) < 2 {
			continue
		}
		if key[0] == "consumer_key" {
			consumer.Token = key[1]
		} else if key[0] == "consumer_secret" {
			consumer.Secret = key[1]
		} else if key[0] == "access_token" {
			access.Token = key[1]
		} else if key[0] == "access_secret" {
			access.Secret = key[1]
		}
	}
	err = scanner.Err()
	if err != nil {
		return nil, nil, err
	}

	if consumer.Token == "" || consumer.Secret == "" {
		fmt.Fprintln(os.Stderr, "Invalid file format.")
		return nil, nil, err
	}
	return consumer, access, err
}

func random(length int) string {
	const base = 36
	size := big.NewInt(base)
	n := make([]byte, length)
	for i, _ := range n {
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
	req.URL.RawQuery = query
	req.Header.Add("Authorize", "Oauth")
	client := new(http.Client)
	resp, err := client.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", err
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func GetRequestToken(consumer *Token) (*Token, error) {
	param1 := "GET&" + url.QueryEscape(request_token_url) + "&"
	param2 := "oauth_consumer_key=" + consumer.Token + "&"
	param2 += "oauth_nonce=" + random(32) + "&"
	param2 += "oauth_signature_method=HMAC-SHA1&"
	param2 += "oauth_timestamp=" + getTimestamp() + "&"
	param2 += "oauth_version=1.0"
	param3 := url.QueryEscape(consumer.Secret) + "&"
	param1 += url.QueryEscape(param2)

	hash := hmac.New(sha1.New, []byte(param3))
	hash.Write([]byte(param1))
	sig := url.QueryEscape(base64.StdEncoding.EncodeToString(hash.Sum(nil)))
	query := param2 + "&oauth_signature=" + sig
	result, err := getToken("GET", request_token_url, query)

	if err != nil {
		return nil, err
	}
	reqToken := new(Token)
	reqToken.Token = strings.Split(strings.Split(result, "&")[0], "=")[1]
	reqToken.Secret = strings.Split(strings.Split(result, "&")[1], "=")[1]
	return reqToken, nil
}

func GetPinUrl(reqtoken *Token) string {
	return authorize_url + reqtoken.Token
}

func GetAccessToken(consumer *Token, access *Token) error {
	reqtoken, err := getRequestToken(consumer)
	if err != nil {
		return err
	}
	pin := getPinCode(reqtoken)

	param1 := "GET&" + url.QueryEscape(access_token_url) + "&"
	param2 := "oauth_consumer_key=" + consumer.Token + "&"
	param2 += "oauth_nonce=" + random(32) + "&"
	param2 += "oauth_signature_method=HMAC-SHA1&"
	param2 += "oauth_timestamp=" + getTimestamp() + "&"
	param2 += "oauth_token=" + reqtoken.Token + "&"
	param2 += "oauth_verifier=" + pin + "&"
	param2 += "oauth_version=1.0"
	param3 := url.QueryEscape(consumer.Secret) + "&"
	param3 += url.QueryEscape(reqtoken.Secret)
	param1 += url.QueryEscape(param2)

	hash := hmac.New(sha1.New, []byte(param3))
	hash.Write([]byte(param1))
	sig := url.QueryEscape(base64.StdEncoding.EncodeToString(hash.Sum(nil)))
	query := param2 + "&oauth_signature=" + sig
	result, err := getToken("GET", access_token_url, query)
	if err != nil {
		return err
	}
	fmt.Println(result)
	return nil
}

func SaveTokens(filename string, consumer *Token, access *Token) {
	output := "consumer_key:" + consumer.Token
	output += "\nconsumer_secret:" + consumer.Secret
	output += "\naccess_token:" + access.Token
	output += "\naccess_secret:" + access.Secret
	ioutil.WriteFile(filename, []byte(output), os.ModePerm)
}


