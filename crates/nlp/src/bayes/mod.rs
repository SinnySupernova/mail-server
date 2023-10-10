/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{collections::HashMap, hash::BuildHasherDefault};

use nohash::NoHashHasher;
use serde::{Deserialize, Serialize};

pub mod bloom;
pub mod classify;
pub mod train;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct BayesModel {
    pub weights: HashMap<TokenHash, Weights, BuildHasherDefault<NoHashHasher<TokenHash>>>,
    pub spam_learns: u32,
    pub ham_learns: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BayesClassifier {
    pub min_token_hits: u32,
    pub min_tokens: u32,
    pub min_prob_strength: f64,
    pub min_learns: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Copy, Clone, PartialEq, Eq)]
pub struct TokenHash {
    h1: u64,
    h2: u64,
}

#[derive(Debug, Serialize, Deserialize, Default, Copy, Clone)]
pub struct Weights {
    spam: u32,
    ham: u32,
}

impl BayesClassifier {
    pub fn new() -> Self {
        BayesClassifier {
            min_token_hits: 2,
            min_tokens: 11,
            min_prob_strength: 0.05,
            min_learns: 200,
        }
    }
}

impl Default for BayesClassifier {
    fn default() -> Self {
        Self::new()
    }
}
