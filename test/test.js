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
require('dotenv').config();
const util = require('util')

const AlmefyAPIClient = require("./../src/almefy-api-client").AlmefyAPIClient;

const api = new AlmefyAPIClient({
                                    apiBaseUrl: "https://api.dev.almefy.com",
                                    apiKey: "002d9d7871c7f3c6d197f051f45ce65857cbb2589ac6f2ffb3c3475c5fcf37a7",
                                    apiSecretBase64: "Bm2RnMLEyZpXW/ri5EeGsc7rmGLLUXGWh+5Z4xufJEbUMV/7LN9TBYlyWrV7SWpbckwbNS1eZJCFFegJxWM3Bg==",
                                    debug: false 
                                }, null);

api.check().then(result => {
    console.log(util.inspect(result, {showHidden: false, depth: null, colors: true}))
});

api.getIdentities().then(result => {
    console.log(util.inspect(result, {showHidden: false, depth: null, colors: true}));
});

// api.getIdentity("john.doe").then(result => {
//     console.log(util.inspect(result, {showHidden: false, depth: null, colors: true}))
// });

// const options = {sendEmail: false}
// api.enrollIdentity("john.doe", options).then(result => {
//     console.log(util.inspect(result, {showHidden: false, depth: null, colors: true}))
// });

// api.deleteIdentity("john.doe").then(result => {
//     console.log(util.inspect(result, {showHidden: false, depth: null, colors: true}))
// });

// api.deleteToken("id-of-token").then(result => {
//     console.log(util.inspect(result, {showHidden: false, depth: null, colors: true}))
// });




