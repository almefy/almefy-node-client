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
var pjson = require('./../package.json');
class AlmefyAPIClient {

  constructor (apiConfig, axiosConfig) {
    
    this.apiCache = {}
    this.apiBaseUrl = apiConfig.apiBaseUrl
    this.apiKey = apiConfig.apiKey
    this.apiSecretBase64 = apiConfig.apiSecretBase64
    this.options = {}

    this.VERSION = pjson.version;
    this.ALMEFY_CHECK = "/v1/entity/check";
    this.ALMEFY_IDENTITIES = "/v1/entity/identities";
    this.ALMEFY_ENROLLMENT = "/v1/entity/identities/enroll";
    this.ALMEFY_TOKENS = "/v1/entity/tokens";
    this.ALMEFY_AUTHENTICATE = "/v1/entity/identities/{identity}/authenticate";
    this.ALMEFY_CONFIGURATION = "/v1/entity/configuration";
    this.ALMEFY_SESSIONS = "/v1/entity/sessions";

    this.ALMEFY_ENROLLMENTS = "/v1/entity/enrollments";
    this.ALMEFY_ENROLLMENTS_STATUS = "/v1/entity/enrollments/{enrollment}/status";
    this.ALMEFY_ENROLLMENT_PATCH = "/v1/entity/enrollments/{enrollment}/expire";
    
    this.GET_REQUEST = "GET";
    this.POST_REQUEST = "POST";
    this.PUT_REQUEST = "PUT";
    this.PATCH_REQUEST = "PATCH";
    this.DELETE_REQUEST = "DELETE";
  
    this.REQUEST_TIMESTAMP_LEEWAY = 60;
  
    this.JSON_DEFAULT_DEPTH    = 512;
    this.BASE64_PADDING_LENGTH = 4;
  
    this.ONE_STEP_ENROLLMENT = "ONE_STEP_ENROLLMENT";
    this.TWO_STEP_ENROLLMENT = "TWO_STEP_ENROLLMENT";   

    const axiosLocalConfig = Object.assign({
        baseURL: this.apiBaseUrl,
        headers: {
        "Accept": "application/json"
        },
        httpsAgent: new https.Agent({  
          rejectUnauthorized: false
        }),
        validateStatus: function (status) {
          // 200	Ok, resource was updated
          // 201	Ok, resource was created
          // 202	Ok, request was accepted
          // 204	Ok, but no content is returned
          // 400 -> Submitted data is invalid, Bad Request, es ist generell was falsch, z.B. kein Body bei einem POST
          // 401	Unauthorized access
          // 403	Forbidden, insufficient credentials
          // 404	Resource not Found
          // 410	Resource is gone
          // 415 -> falsches Format, also wenn jemand XML schickt, JSON aber verlangt ist
          // 422 -> Unprocessable Entity, das ist der richtige Wert, wenn Validierung fehl schlägt.
          // 423	Resource is locked
          // 429	Too many requests
          // 500	Something went wrong on Almefy's end
          const validCodes = [200, 201, 202, 204, 400, 401, 403, 404, 410, 415, 422, 423, 429];
          return (validCodes.includes(status));
        }
    }, axiosConfig)
    this._axios = axios.create(axiosLocalConfig);
    if (apiConfig.debug) {
      this._axios.interceptors.request.use(request => {
        console.log('Starting Request', JSON.stringify(request, null, 2));
        return request;
      })
    }

  }

  axios () {
    return this._axios;
  }

  // setHeader (header, value) {
  //   this._axios.defaults.headers[header] = value
  // }

  // setHeaders (headers) {
  //   for (let header in headers) {
  //     this.setHeader(header, headers[header])
  //   }
  // }

  async createApiRequest(method, url, bodyJson = null, createBearerToken = true) {

    const options = {
      method: method,
      url: url, 
      data: bodyJson,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": `Almefy Node Client ${this.VERSION} (node version ${process.version})`,
        "X-Client-Version": `${this.VERSION}`,
      }
      
    }

    if (createBearerToken) {
      const signedToken = this.createApiToken(method, url, bodyJson);
      options.headers["Authorization"] = `Bearer ${signedToken}`;
    }
    
    const response = await this._axios.request(options);
    return response;

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
    };

    const secretKeyBase64 = Buffer.from(this.apiSecretBase64, "base64");
    const signedToken = jwt.sign(claim, secretKeyBase64);
    return signedToken;

  }

  async check() {

    const bodyJson = JSON.stringify({
      "message": "ping",
    });
    const response = await this.createApiRequest(this.POST_REQUEST, this.ALMEFY_CHECK, bodyJson);
    return (response.status===200 && response.data.message=="pong")? true : false;

  }

  async getConfiguration() {

    const response = await this.createApiRequest(this.GET_REQUEST, this.ALMEFY_CONFIGURATION, null);
    return (response.status===200 && response.data)? response.data : null;

  }

  async setConfiguration(configuration) {

    const options = JSON.stringify({
      "websiteUrl" : configuration.websiteUrl ? configuration.websiteUrl : null,
      "authenticationUrl" : configuration.authenticationUrl ? configuration.authenticationUrl : null, 
      "supportSessions" : configuration.supportSessions ? configuration.supportSessions : false
    });

    const response = await this.createApiRequest(this.PATCH_REQUEST, this.ALMEFY_CONFIGURATION, options);
    return (response.status===200 && response.data)? response.data : null;

  }

  async getIdentities() {

    const response = await this.createApiRequest(this.GET_REQUEST, this.ALMEFY_IDENTITIES, null);
    return (response.status===200 && response.data)? response.data : null;

  }

  async getIdentity(identifier) {

    const response = await this.createApiRequest(this.GET_REQUEST, `${this.ALMEFY_IDENTITIES}/${encodeURIComponent(identifier)}`, null);
    return (response.status===200 && response.data)? response.data : null;

  }

  // getSession(sessionsId)
  // getSessions(sessionsToUpdate = [])
  // updateSessions(sessions = [])

  async logoutSession(sessionId) {

    const response = await this.createApiRequest(this.DELETE_REQUEST, `${this.ALMEFY_SESSIONS}/${sessionId}}`, null);

  }

  async enrollIdentity(identifier, options = []) {

    const bodyJson = Object.assign({
        "enrollmentType": this.ONE_STEP_ENROLLMENT,
        "nickname": null,
        "sendEmail": false,
        "sendEmailTo": "",
        "sendEmailLocale": "de-DE",
        "sendEmailTimeZone": "Europe/Berlin",
        "role": "ROLE_USER",
        "timeout": 3600
    }, options);

    bodyJson["identifier"] = `${identifier}`; // This cannot be changed by options
    const response = await this.createApiRequest(this.POST_REQUEST, this.ALMEFY_ENROLLMENT, JSON.stringify(bodyJson));
    return (response.status===200 || response.status===201)? response.data : null;

  }
  
  //deprecated
  async provisionIdentity(identifier, options = []) {

    return this.enrollIdentity(identifier, options);

  }

  async deleteIdentity(identifier) {

    const response = await this.createApiRequest(this.DELETE_REQUEST, `${this.ALMEFY_IDENTITIES}/${encodeURIComponent(identifier)}`, null);
    return (response.status===200 || response.status===201)? response.data : null;

  }

  async deleteToken(id) {

    const response = await this.createApiRequest(this.DELETE_REQUEST, `${this.ALMEFY_TOKENS}/${encodeURIComponent(id)}`, null);
    return (response.status===200 || response.status===201)? response.data : null;

  }

  //deprecated
  async verifyToken(token) {

    return this.authenticate(token); 

  }

  async authenticate(token) {

    const authenticateUrl = this.ALMEFY_AUTHENTICATE.replace("{identity}", token.sub);
    const bodyJson = { "challenge": token.jti, "otp": token.otp };
    var response = await this.createApiRequest(this.POST_REQUEST, authenticateUrl, JSON.stringify(bodyJson), false);

    return (response.status===200)? token.sub : null;

  }

  async getEnrollments() {

    const response = await this.createApiRequest(this.GET_REQUEST, this.ALMEFY_ENROLLMENTS, null);
    return (response.status===200 && response.data)? response.data : null;

  }

  async getEnrollment(id) {

    const response = await this.createApiRequest(this.GET_REQUEST, `${this.ALMEFY_ENROLLMENTS}/${id}`, null);
    return (response.status===200 && response.data)? response.data : null;   

  }

  async getEnrollmentStatus(id) {

    const getEnrollmentStatusUrl = this.ALMEFY_ENROLLMENTS_STATUS.replace("{enrollment}", id);
    const response = await this.createApiRequest(this.GET_REQUEST, getEnrollmentStatusUrl, null);
    return (response.status===200 && response.data)? response.data : null;

  }
  
  async revokeEnrollment(id) {

    const revokeEnrollmentUrl = this.ALMEFY_ENROLLMENT_PATCH.replace("{enrollment}", id);
    const response = await this.createApiRequest(this.PATCH_REQUEST, revokeEnrollmentUrl, null);
    return (response.status===200 || response.status===201)? response.data : null;

  }

  verifyJwt(jwttoken) {
    
    const secretKeyBase64 = Buffer.from(this.apiSecretBase64, "base64");
    const token = jwt.verify(jwttoken, secretKeyBase64, {clockTolerance: this.REQUEST_TIMESTAMP_LEEWAY});
    return token;

  }

  decodeJwt(jwttoken) {

    const token = jwt.decode(jwttoken, {clockTolerance: this.REQUEST_TIMESTAMP_LEEWAY});
    return token;

  }

}

exports.AlmefyAPIClient = AlmefyAPIClient
