//! Object identifiers relevant to PACE.


use rasn::types::Oid;


macro_rules! pace_oid {
    ($name:ident $(, $number:expr)* $(,)?) => {
        pub const $name: &'static Oid = Oid::const_new(&[0, 4, 0, 127, 0, 7, 2, 2, 4 $(, $number)*]);
    };
}

pace_oid!(PACE_OID_PREFIX);

pace_oid!(PACE_DH_GM,                   1);
pace_oid!(PACE_DH_GM_3DES_CBC_CBC,      1, 1);
pace_oid!(PACE_DH_GM_AES_CBC_CMAC_128,  1, 2);
pace_oid!(PACE_DH_GM_AES_CBC_CMAC_192,  1, 3);
pace_oid!(PACE_DH_GM_AES_CBC_CMAC_256,  1, 4);

pace_oid!(PACE_ECDH_GM,                     2);
pace_oid!(PACE_ECDH_GM_3DES_CBC_CBC,        2, 1);
pace_oid!(PACE_ECDH_GM_AES_CBC_CMAC_128,    2, 2);
pace_oid!(PACE_ECDH_GM_AES_CBC_CMAC_192,    2, 3);
pace_oid!(PACE_ECDH_GM_AES_CBC_CMAC_256,    2, 4);

pace_oid!(PACE_DH_IM,                   3);
pace_oid!(PACE_DH_IM_3DES_CBC_CBC,      3, 1);
pace_oid!(PACE_DH_IM_AES_CBC_CMAC_128,  3, 2);
pace_oid!(PACE_DH_IM_AES_CBC_CMAC_192,  3, 3);
pace_oid!(PACE_DH_IM_AES_CBC_CMAC_256,  3, 4);

pace_oid!(PACE_ECDH_IM,                     4);
pace_oid!(PACE_ECDH_IM_3DES_CBC_CBC,        4, 1);
pace_oid!(PACE_ECDH_IM_AES_CBC_CMAC_128,    4, 2);
pace_oid!(PACE_ECDH_IM_AES_CBC_CMAC_192,    4, 3);
pace_oid!(PACE_ECDH_IM_AES_CBC_CMAC_256,    4, 4);

// 5 is unused (theoretically DH-CAM)

pace_oid!(PACE_ECDH_CAM,                    6);
// 6.1 is unused (theoretically ECDH-CAM with 3DES)
pace_oid!(PACE_ECDH_CAM_AES_CBC_CMAC_128,   6, 2);
pace_oid!(PACE_ECDH_CAM_AES_CBC_CMAC_192,   6, 3);
pace_oid!(PACE_ECDH_CAM_AES_CBC_CMAC_256,   6, 4);
