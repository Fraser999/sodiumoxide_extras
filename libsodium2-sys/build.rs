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

extern crate gcc;
// extern crate num_cpus;
#[macro_use]
extern crate unwrap;

use std::env;
use std::process::Command;

fn main() {
    let current_dir = unwrap!(env::current_dir());
    gcc::Config::new()
        .include("libsodium/src/libsodium/include/sodium")
        .file("libsodium/src/libsodium/crypto_sign/crypto_sign.c")
        .file("libsodium/src/libsodium/crypto_sign/ed25519/sign_ed25519_api.c")
        .file("libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c")
        .file("libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c")
        .file("libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c")
        .file("libsodium/src/libsodium/crypto_sign/ed25519/ref10/obsolete.c")
        .file("libsodium/src/libsodium/crypto_stream/aes128ctr/stream_aes128ctr_api.c")
        .file("libsodium/src/libsodium/crypto_stream/aes128ctr/portable/afternm_aes128ctr.c")
        .file("libsodium/src/libsodium/crypto_stream/aes128ctr/portable/int128_aes128ctr.c")
        .file("libsodium/src/libsodium/crypto_stream/aes128ctr/portable/stream_aes128ctr.c")
        .file("libsodium/src/libsodium/crypto_stream/aes128ctr/portable/consts_aes128ctr.c")
        .file("libsodium/src/libsodium/crypto_stream/aes128ctr/portable/beforenm_aes128ctr.c")
        .file("libsodium/src/libsodium/crypto_stream/aes128ctr/portable/xor_afternm_aes128ctr.c")
        .file("libsodium/src/libsodium/crypto_stream/salsa208/stream_salsa208_api.c")
        .file("libsodium/src/libsodium/crypto_stream/salsa208/ref/xor_salsa208.c")
        .file("libsodium/src/libsodium/crypto_stream/salsa208/ref/stream_salsa208.c")
        .file("libsodium/src/libsodium/crypto_stream/salsa20/ref/xor_salsa20_ref.c")
        .file("libsodium/src/libsodium/crypto_stream/salsa20/ref/stream_salsa20_ref.c")
        .file("libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20_api.c")
        .file("libsodium/src/libsodium/crypto_stream/xsalsa20/ref/xor_xsalsa20.c")
        .file("libsodium/src/libsodium/crypto_stream/xsalsa20/ref/stream_xsalsa20.c")
        .file("libsodium/src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20_api.c")
        .file("libsodium/src/libsodium/crypto_stream/crypto_stream.c")
        .file("libsodium/src/libsodium/crypto_stream/salsa2012/stream_salsa2012_api.c")
        .file("libsodium/src/libsodium/crypto_stream/salsa2012/ref/stream_salsa2012.c")
        .file("libsodium/src/libsodium/crypto_stream/salsa2012/ref/xor_salsa2012.c")
        .file("libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c")
        .file("libsodium/src/libsodium/crypto_stream/chacha20/ref/stream_chacha20_ref.c")
        .file("libsodium/src/libsodium/crypto_stream/chacha20/vec/stream_chacha20_vec.c")
        .file("libsodium/src/libsodium/crypto_auth/crypto_auth.c")
        .file("libsodium/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512_api.c")
        .file("libsodium/src/libsodium/crypto_auth/hmacsha512/cp/hmac_hmacsha512.c")
        .file("libsodium/src/libsodium/crypto_auth/hmacsha512/cp/verify_hmacsha512.c")
        .file("libsodium/src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256_api.c")
        .file("libsodium/src/libsodium/crypto_auth/hmacsha512256/cp/hmac_hmacsha512256.c")
        .file("libsodium/src/libsodium/crypto_auth/hmacsha512256/cp/verify_hmacsha512256.c")
        .file("libsodium/src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256_api.c")
        .file("libsodium/src/libsodium/crypto_auth/hmacsha256/cp/verify_hmacsha256.c")
        .file("libsodium/src/libsodium/crypto_auth/hmacsha256/cp/hmac_hmacsha256.c")
        .file("libsodium/src/libsodium/randombytes/nativeclient/randombytes_nativeclient.c")
        .file("libsodium/src/libsodium/randombytes/randombytes.c")
        .file("libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c")
        .file("libsodium/src/libsodium/randombytes/salsa20/randombytes_salsa20_random.c")
        .file("libsodium/src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24_api.c")
        .file("libsodium/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24.c")
        .file("libsodium/src/libsodium/crypto_shorthash/crypto_shorthash.c")
        .file("libsodium/src/libsodium/crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.c")
        .file("libsodium/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_invert.c")
        .file("libsodium/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe_frombytes_sandy2x.c")
        .file("libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c")
        .file("libsodium/src/libsodium/crypto_scalarmult/curve25519/donna_c64/curve25519_donna_c64.c")
        .file("libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c")
        .file("libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c")
        .file("libsodium/src/libsodium/crypto_core/hchacha20/core_hchacha20.c")
        .file("libsodium/src/libsodium/crypto_core/curve25519/ref10/curve25519_ref10.c")
        .file("libsodium/src/libsodium/crypto_core/hsalsa20/core_hsalsa20_api.c")
        .file("libsodium/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20.c")
        .file("libsodium/src/libsodium/crypto_core/salsa208/ref/core_salsa208.c")
        .file("libsodium/src/libsodium/crypto_core/salsa208/core_salsa208_api.c")
        .file("libsodium/src/libsodium/crypto_core/salsa20/core_salsa20_api.c")
        .file("libsodium/src/libsodium/crypto_core/salsa20/ref/core_salsa20.c")
        .file("libsodium/src/libsodium/crypto_core/salsa2012/ref/core_salsa2012.c")
        .file("libsodium/src/libsodium/crypto_core/salsa2012/core_salsa2012_api.c")
        .file("libsodium/src/libsodium/crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c")
        .file("libsodium/src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c")
        .file("libsodium/src/libsodium/sodium/core.c")
        .file("libsodium/src/libsodium/sodium/version.c")
        .file("libsodium/src/libsodium/sodium/runtime.c")
        .file("libsodium/src/libsodium/sodium/utils.c")
        .file("libsodium/src/libsodium/crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c")
        .file("libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c")
        .file("libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c")
        .file("libsodium/src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c")
        .file("libsodium/src/libsodium/crypto_hash/crypto_hash.c")
        .file("libsodium/src/libsodium/crypto_hash/sha256/hash_sha256_api.c")
        .file("libsodium/src/libsodium/crypto_hash/sha256/cp/hash_sha256.c")
        .file("libsodium/src/libsodium/crypto_hash/sha512/hash_sha512_api.c")
        .file("libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512.c")
        .file("libsodium/src/libsodium/crypto_box/crypto_box_easy.c")
        .file("libsodium/src/libsodium/crypto_box/crypto_box_seal.c")
        .file("libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/keypair_curve25519xsalsa20poly1305.c")
        .file("libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/box_curve25519xsalsa20poly1305.c")
        .file("libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/before_curve25519xsalsa20poly1305.c")
        .file("libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/after_curve25519xsalsa20poly1305.c")
        .file("libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305_api.c")
        .file("libsodium/src/libsodium/crypto_box/crypto_box.c")
        .file("libsodium/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c")
        .file("libsodium/src/libsodium/crypto_secretbox/crypto_secretbox.c")
        .file("libsodium/src/libsodium/crypto_secretbox/xsalsa20poly1305/ref/box_xsalsa20poly1305.c")
        .file("libsodium/src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305_api.c")
        .file("libsodium/src/libsodium/crypto_generichash/crypto_generichash.c")
        .file("libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-compress-sse41.c")
        .file("libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-compress-ssse3.c")
        .file("libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-compress-ref.c")
        .file("libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-ref.c")
        .file("libsodium/src/libsodium/crypto_generichash/blake2/ref/generichash_blake2b.c")
        .file("libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-compress-avx2.c")
        .file("libsodium/src/libsodium/crypto_generichash/blake2/generichash_blake2_api.c")
        .file("libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c")
        .file("libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c")
        .file("libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c")
        .file("libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c")
        .file("libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c")
        .file("libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c")
        .file("libsodium/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c")
        .file("libsodium/src/libsodium/crypto_pwhash/argon2/argon2-core.c")
        .file("libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c")
        .file("libsodium/src/libsodium/crypto_pwhash/argon2/blake2b-long.c")
        .file("libsodium/src/libsodium/crypto_pwhash/argon2/pwhash_argon2i.c")
        .file("libsodium/src/libsodium/crypto_pwhash/argon2/argon2.c")
        .file("libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ssse3.c")
        .file("libsodium/src/libsodium/crypto_pwhash/crypto_pwhash.c")
        .file("libsodium/src/libsodium/crypto_verify/32/ref/verify_32.c")
        .file("libsodium/src/libsodium/crypto_verify/32/verify_32_api.c")
        .file("libsodium/src/libsodium/crypto_verify/16/verify_16_api.c")
        .file("libsodium/src/libsodium/crypto_verify/16/ref/verify_16.c")
        .file("libsodium/src/libsodium/crypto_verify/64/ref/verify_64.c")
        .file("libsodium/src/libsodium/crypto_verify/64/verify_64_api.c")
        .compile("libsodium.a");


    // let cores = num_cpus::get();
    // let out_dir = unwrap!(env::var("OUT_DIR"));
    // println!("Out: {}/installed  --  Cur: {} -- Cores: {}",
    //          out_dir,
    //          current_dir.display(),
    //          cores);
    // let _ = unwrap!(Command::new("./configure")
    //     .args(&["--enable-shared=no",
    //             "--disable-pie",
    //             &format!("--prefix={}/installed", out_dir)])
    //     .current_dir(current_dir.join("libsodium"))
    //     .status());
    // let _ = unwrap!(Command::new("make")
    //     .arg(&format!("-j{}", cores))
    //     .current_dir(current_dir.join("libsodium"))
    //     .status());
    // let _ = unwrap!(Command::new("make")
    //     .arg("install")
    //     .current_dir(current_dir.join("libsodium"))
    //     .status());
}
