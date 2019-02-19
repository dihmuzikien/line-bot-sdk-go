// Copyright 2016 LINE Corporation
//
// LINE Corporation licenses this file to you under the Apache License,
// version 2.0 (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at:
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package linebot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
)

// ParseRequest method
func (client *Client) ParseRequest(requestSignature string, r io.Reader) ([]*Event, error) {
	return ParseRequest(client.channelSecret, requestSignature, r)
}

// ParseRequest func
func ParseRequest(channelSecret, requestSignature string, r io.Reader) ([]*Event, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if !validateSignature(channelSecret, requestSignature, body) {
		return nil, ErrInvalidSignature
	}

	request := &struct {
		Events []*Event `json:"events"`
	}{}
	if err = json.Unmarshal(body, request); err != nil {
		return nil, err
	}
	return request.Events, nil
}

func validateSignature(channelSecret, signature string, body []byte) bool {
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	hash := hmac.New(sha256.New, []byte(channelSecret))

	_, err = hash.Write(body)
	if err != nil {
		return false
	}

	return hmac.Equal(decoded, hash.Sum(nil))
}
