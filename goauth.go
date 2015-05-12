package main

import (
	"fmt"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha1"
	"math/big"
	"strconv"
	"time"
	"bufio"
	"os"
	"strings"
	"net/url"
	"net/http"
	"io/ioutil"
	"encoding/base64"
)

type Config struct {
	ConsumerKey string
	ConsumerSecret string
	Nonce string
	Method string
	Timestamp string
	Token string
	Verifier string
	Version string
}

type Token struct {
	Token string
	Secret string
}


func (conf *Config) Init() {
	conf.Method = "HMAC-SHA1"
	conf.Version = "1.0"
	conf.random(32)
	conf.Timestamp = strconv.FormatInt(time.Now().Unix(), 10)
}

func (conf *Config) inputKeys() {
	fp, err := os.Open("keys")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open keys file.")
		os.Exit(1)
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		key := strings.Split(scanner.Text(), ":")
		if len(key) < 2 {
			fmt.Fprintln(os.Stderr, "Invalid file format.")
			os.Exit(1)
		}
		if key[0] == "consumer_key" {
			conf.ConsumerKey = key[1]
		} else if key[0] == "consumer_secret" {
			conf.ConsumerSecret = key[1]
		}
	}
	err = scanner.Err()
	if err != nil {
		os.Exit(1)
	}
}

func (conf *Config) random(length int) {
	const base = 36
	size := big.NewInt(base)
	n := make([]byte, length)
	for i, _ := range n {
		c, _ := rand.Int(rand.Reader, size)
		n[i] = strconv.FormatInt(c.Int64(), base)[0]
	}
	conf.Nonce = string(n)
	conf.inputKeys()
}

func GetToken(url string, query string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to request")
		os.Exit(1)
	}
	req.URL.RawQuery = query
	req.Header.Add("Authorize", "Oauth")
	client := new(http.Client)
	resp, err := client.Do(req)
	defer resp.Body.Close()

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read.")
		os.Exit(1)
	}
	return string(buf)
}

func main() {
	endpoint := "https://api.twitter.com/oauth/request_token"
	var conf Config
	conf.Init()
	param1 := "GET&" + url.QueryEscape(endpoint) + "&"
	param2 := "oauth_consumer_key=" + conf.ConsumerKey + "&"
	param2 += "oauth_nonce=" + conf.Nonce + "&"
	param2 += "oauth_signature_method=" + conf.Method + "&"
	param2 += "oauth_timestamp=" + conf.Timestamp + "&"
	param2 += "oauth_version=" + conf.Version
	param3 := url.QueryEscape(conf.ConsumerSecret) + "&"

	param1 += url.QueryEscape(param2)
	fmt.Println(param1)

	hash := hmac.New(sha1.New, []byte(param3))
	hash.Write([]byte(param1))
	signature := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	encsignature := url.QueryEscape(signature)

	request := param2 + "&oauth_signature=" + encsignature
	fmt.Println(request)

	result := GetToken(endpoint, request)
	fmt.Println(result)

	tokens := strings.Split(result, "&")
	token := Token{
		strings.Split(tokens[0], "=")[1],
		strings.Split(tokens[1], "=")[1],
	}
	fmt.Println(token)

	pinurl := "http://twitter.com/oauth/authorize?oauth_token=" + token.Token

	fmt.Println(pinurl)

	fmt.Print("Input PIN: ")
	var pin string
	fmt.Scan(&pin)
	fmt.Println(pin)

	endpoint = "https://api.twitter.com/oauth/access_token"
	param1 = "GET&" + url.QueryEscape(endpoint) + "&"
	param2 = "oauth_consumer_key=" + conf.ConsumerKey + "&"
	param2 += "oauth_nonce=" + conf.Nonce + "&"
	param2 += "oauth_signature_method=" + conf.Method + "&"
	param2 += "oauth_timestamp=" + conf.Timestamp + "&"
	param2 += "oauth_token=" + token.Token + "&"
	param2 += "oauth_verifier=" + pin + "&"
	param2 += "oauth_version=" + conf.Version
	param3 = url.QueryEscape(conf.ConsumerSecret) + "&" + url.QueryEscape(token.Secret)

	param1 += url.QueryEscape(param2)
	hash = hmac.New(sha1.New, []byte(param3))
	hash.Write([]byte(param1))
	signature = base64.StdEncoding.EncodeToString(hash.Sum(nil))
	encsignature = url.QueryEscape(signature)

	request = param2 + "oauth_signature=" + encsignature

	result = GetToken(endpoint, request)
	fmt.Println(result)
}
