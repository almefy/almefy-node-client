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

import Token from './token'

class Identity {

    public constructor({id, createdAt, locked, identifier, nickname, name, tokens} = {})
    {
        this.id = id;
        this.createdAt = createdAt;
        this.locked = locked;
        this.identifier = identifier;
        this.nickname = nickname;
        this.name = name;
        this.token = tokens;
    }    

}