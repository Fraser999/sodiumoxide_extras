// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

extern crate libc;

use libc::{c_char, c_int, c_void, size_t, uint32_t};

#[repr(C)]
pub struct FunctionPointers {
    pub implementation_name: extern "C" fn() -> *const c_char,
    pub random: extern "C" fn() -> uint32_t,
    pub stir: Option<extern "C" fn()>,
    pub uniform: Option<extern "C" fn(upper_bound: uint32_t) -> uint32_t>,
    pub buf: extern "C" fn(buf: *mut c_void, size: size_t),
    pub close: Option<extern "C" fn() -> c_int>,
}

extern "C" {
    pub fn sodium_init() -> c_int;
    pub fn randombytes_set_implementation(function_pointers: *mut FunctionPointers) -> c_int;
    pub fn sodium_version_string() -> *const c_char;
}
