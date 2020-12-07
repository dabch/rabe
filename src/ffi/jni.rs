extern crate jni;

use super::*;
use self::jni::JNIEnv;
use self::jni::objects::{JClass, JString};
use self::jni::sys::{jstring};
use schemes::lsw::*;

#[no_mangle]
pub unsafe extern fn Java_de_fraunhofer_aisec_kpabe_encrypt(env: JNIEnv, _: JClass, java_pattern: JString) -> jstring {
    let (_pk, _msk) = setup();
}