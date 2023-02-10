#!/usr/bin/env node
/*
 * Copyright (c) 2022 Almefy GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var cryptoJS = require("crypto-js");
var jwt = require("jsonwebtoken");
var axios = require("axios");
const util = require('util')
var https = require('https');

class AlmefyAPIClient {

  constructor (apiConfig, axiosConfig) {
    
    this.apiCache = {}
    this.apiBaseUrl = apiConfig.apiBaseUrl
    this.apiKey = apiConfig.apiKey
    this.apiSecretBase64 = apiConfig.apiSecretBase64
    this.options = {}

    this.VERSION = "0.0.1"
    this.ALMEFY_CHECK = "/v1/entity/check"
    this.ALMEFY_IDENTITIES = "/v1/entity/identities"
    this.ALMEFY_ENROLLMENTS = "/v1/entity/identities/enroll"
    this.ALMEFY_TOKENS = "/v1/entity/tokens"
    this.ALMEFY_AUTHENTICATE = "/v1/entity/identities/{identity}/authenticate"
    
    this.GET_REQUEST = "GET"
    this.POST_REQUEST = "POST"
    this.PUT_REQUEST = "PUT"
    this.PATCH_REQUEST = "PATCH"
    this.DELETE_REQUEST = "DELETE"
  
    this.REQUEST_TIMESTAMP_LEEWAY = 60
  
    this.JSON_DEFAULT_DEPTH    = 512
    this.BASE64_PADDING_LENGTH = 4
  
    this.ONE_STEP_ENROLLMENT = "ONE_STEP_ENROLLMENT"
    this.TWO_STEP_ENROLLMENT = "TWO_STEP_ENROLLMENT"    

    const axiosLocalConfig = Object.assign({
        baseURL: this.apiBaseUrl,
        headers: {
        "Accept": "application/json"
        },
        httpsAgent: new https.Agent({  
          rejectUnauthorized: false
        }),
    }, axiosConfig)
    this._axios = axios.create(axiosLocalConfig)
    if (apiConfig.debug) {
      this._axios.interceptors.request.use(request => {
        console.log('Starting Request', JSON.stringify(request, null, 2))
        return request
      })
    }

  }

  axios () {
    return this._axios
  }

  // setHeader (header, value) {
  //   this._axios.defaults.headers[header] = value
  // }

  // setHeaders (headers) {
  //   for (let header in headers) {
  //     this.setHeader(header, headers[header])
  //   }
  // }

  async createApiRequest(method, url, bodyJson = null) {

    const signedToken = this.createApiToken(method, url, bodyJson)

    const options = {
      method: method,
      url: url, 
      data: bodyJson,
      headers: {
        "Authorization": `Bearer ${signedToken}`,
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": `Almefy Node Client ${this.VERSION} (node version ${process.version})`,
        "X-Client-Version": `${this.VERSION}`,
      }
    }
    const response = await this._axios.request(options)
    return response

  }

  createApiToken(method, url, bodyJson) {

    const mytime = Math.floor(new Date().getTime() / 1000);
    const claim = {
      "iss": this.apiKey,
      "aud": this.apiBaseUrl,
      "iat": mytime,
      "nbf": mytime,
      "exp": mytime+10,
      "method": method,
      "url": this.apiBaseUrl + url,
      "bodyHash": cryptoJS.SHA256(bodyJson).toString()
    }
    const secretKeyBase64 = Buffer.from(this.apiSecretBase64, "base64")
    const signedToken = jwt.sign(claim, secretKeyBase64)
    return signedToken

  }

  async check() {

    const bodyJson = JSON.stringify({
      "message": "ping",
    });
    const response = await this.createApiRequest(this.POST_REQUEST, this.ALMEFY_CHECK, bodyJson)
    return (response.status===200 && response.data.message=="pong")? true : false

  }

  async getIdentities() {

    const response = await this.createApiRequest(this.GET_REQUEST, this.ALMEFY_IDENTITIES, null)
    return (response.status===200 && response.data)? response.data : null

  }

  async getIdentity(identifier) {

    const response = await this.createApiRequest(this.GET_REQUEST, `${this.ALMEFY_IDENTITIES}/${encodeURIComponent(identifier)}`, null)
    console.log(identifier)
    return (response.status===200 && response.data)? response.data : null    

  }

  async enrollIdentity(identifier, options = []) {

    const bodyJson = Object.assign({
        "enrollmentType": this.ONE_STEP_ENROLLMENT,
        "nickname": null,
        "sendEmail": false,
        "sendEmailTo": "",
        "sendEmailLocale": "en_US",
    }, options)

    bodyJson["identifier"] = `${identifier}` // This cannot be changed by options
    const response = await this.createApiRequest(this.POST_REQUEST, this.ALMEFY_ENROLLMENTS, JSON.stringify(bodyJson))

    return (response.status===200 || response.status===201)? response.data : null;

  }
  
  //deprecated
  async provisionIdentity(identifier, options = []) {

    return this.enrollIdentity(identifier, options);

  }

  async deleteIdentity(identifier) {

    const response = await this.createApiRequest(this.DELETE_REQUEST, `${this.ALMEFY_IDENTITIES}/${encodeURIComponent(identifier)}`, null)
    return (response.status===200 || response.status===201)? response.data : null;

  }

  async deleteToken(id) {

    const response = await this.createApiRequest(this.DELETE_REQUEST, `${this.ALMEFY_TOKENS}/${encodeURIComponent(id)}`, null)
    return (response.status===200 || response.status===201)? response.data : null;
    
  }

  //deprecated
  async verifyToken(token) {
    return this.authenticate(token); 
  }

  async authenticate(token) {

    const authenticateUrl = this.ALMEFY_AUTHENTICATE.replace("{identity}", token.sub);
    const bodyJson = { "challenge": token.jti, "otp": token.otp };
    await this.createApiRequest(this.POST_REQUEST, authenticateUrl, JSON.stringify(bodyJson));

    return (response.status===200)? true : false;

  }

  decodeJwt(jwt) {
    const token = jwt.verify(jwt, this.secretKeyBase64, {clockTolerance: this.REQUEST_TIMESTAMP_LEEWAY});
    return token;
  }

}

exports.AlmefyAPIClient = AlmefyAPIClient