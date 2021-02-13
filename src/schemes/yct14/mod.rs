//!
//! * Developped by Xuanxia Yao, Zhi Chen, Ye Tian, "A lightweight attribute-based encryption scheme for the Internet of things"
//! * Published in: Future Generation Computer Systems
//! * Available From: http://www.sciencedirect.com/science/article/pii/S0167739X14002039
//! * Type: encryption (key-policy attribute-based)
//! * Setting: No pairing
//! * Authors: Georg Bramm
//! * Date:	01/2021
//!
//! # Examples
//!
//! ```
//! use rabe::schemes::yct14::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
//! let (pk, msk) = setup(vec!["A".to_string(), "B".to_string(), "C".to_string()]);
//!let plaintext = String::from("our plaintext!").into_bytes();
//!let policy = String::from(r#""A" or "B""#);
//!let ct_kp: Yct14AbeCiphertext = encrypt(&pk, &vec!["A".to_string(), "B".to_string()], &plaintext).unwrap();
//!let sk: Yct14AbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
//!assert_eq!(decrypt(&sk, &ct_kp).unwrap(), plaintext);
//! ```
use rabe_bn::{Fr, Gt};
use utils::{
    // secretsharing::{gen_shares_policy, calc_coefficients, calc_pruned},
    aes::*
};
use rand::Rng;
// use utils::po licy::pest::{PolicyLanguage, parse};
use RabeError;
// use std::ops::Mul;
use heapless::{Vec, consts};

use rand::RngCore;

use serde::{Serialize, Deserialize};

type S = consts::U64;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Yct14Attribute<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<Yct14Type>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum Yct14Type {
    Public(Gt),
    Private(Fr),
}

impl Yct14Type {
    pub fn public(&self) -> Result<Gt, RabeError> {
        match self {
            Yct14Type::Public(g) => Ok(g.clone()),
            _ => Err(RabeError::new("no public value (Gt) found"))
        }
    }
    pub fn  private(&self) -> Result<Fr, RabeError> {
        match self {
            Yct14Type::Private(fr) => Ok(fr.clone()),
            _ => Err(RabeError::new("no private value (Fr) found"))
        }
    }
}

impl<'a> Yct14Attribute<'a> {
    pub fn new(name: &'a str, g: Gt, rng: &mut dyn RngCore) -> (Yct14Attribute<'a>, Yct14Attribute<'a>) {
        // random fr
        let si: Fr = rng.gen();
        (
            // public attribute part
            Yct14Attribute {
                name: name,
                node: Some(Yct14Type::Public(g.pow(si))),
            },
            //private attribute part
            Yct14Attribute {
                name,
                node: Some(Yct14Type::Private(si)),
            }
        )
    }
    // pub fn private_from(input: (String, Fr), msk: &Yct14AbeMasterKey) -> Result<Yct14Attribute, RabeError> {
    //     match msk.get_private(&input.0) {
    //         Ok(si) => Ok(
    //             Yct14Attribute {
    //                 name: input.0,
    //                 node: Some(
    //                     Yct14Type::Private(
    //                         input.1.mul(si.inverse().unwrap())
    //                     )
    //                 )
    //             }
    //         ),
    //         Err(e) => Err(e)
    //     }

    // }
    pub fn public_from(name: &'a str, pk: &Yct14AbePublicKey, k: Fr) -> Yct14Attribute<'a> {
        Yct14Attribute {
            name: name,
            node: pk.attributes
                .clone()
                .into_iter()
                .filter(|attribute| attribute.name == name)
                .map(|attribute| match &attribute.node {
                    Some(node) => {
                        match node {
                            Yct14Type::Public(public) => {
                                Some(Yct14Type::Public(public.pow(k)))
                            },
                            _ => panic!("attribute has no public node value"),
                        }
                    },
                    None => panic!("attribute has no public node"),
                })
                .nth(0)
                .unwrap()
        }
    }
}

/// A Public Key (PK)
#[derive(Serialize, PartialEq, Clone)]
pub struct Yct14AbePublicKey<'name, 'atts> {
    g: Gt,
    #[serde(borrow)]
    attributes: &'atts [Yct14Attribute<'name>]
}

/// A Master Key (MSK)
// #[derive(Serialize, Deserialize, PartialEq, Clone)]
// pub struct Yct14AbeMasterKey {
//     s: Fr,
//     attributes: Vec<Yct14Attribute>
// }

// impl Yct14AbeMasterKey {
//     pub fn get_private(&self, attribute: &String) -> Result<Fr, RabeError> {
//         let res: Option<Fr> = self.attributes
//             .clone()
//             .into_iter()
//             .filter(|a| a.name.as_str() == attribute && a.node.is_some())
//             .map(|a| match a.node.unwrap().private() {
//                 Ok(node_value) => node_value,
//                 Err(e) => panic!("no private node value: {}",e)
//             } )
//             .nth(0);
//         res.ok_or(RabeError::new(&format!("no private key found for {}", attribute)))
//     }
// }

/// A Secret User Key (SK)
// #[derive(Serialize, Deserialize, PartialEq, Clone)]
// pub struct Yct14AbeSecretKey {
//     policy: (String, PolicyLanguage),
//     du: Vec<Yct14Attribute>,
// }

// impl Yct14AbeSecretKey {
//     pub fn get_private(&self, attribute: &String) -> Result<Fr, RabeError> {
//         let res: Option<Fr> = self.du
//             .clone()
//             .into_iter()
//             .filter(|a| a.name.as_str() == attribute)
//             .map(|a| match a.node.unwrap().private() {
//                 Ok(node_value) => node_value,
//                 Err(e) => panic!("no private node value: {}",e)
//             } )
//             .nth(0);
//         res.ok_or(RabeError::new(&format!("no private key found for {}", attribute)))
//     }
// }

/// A Ciphertext (CT)
#[derive(Serialize, PartialEq)]
pub struct Yct14AbeCiphertext<'name, 'data> {
    attributes: Vec<Yct14Attribute<'name>, S>,
    ct: &'data mut [u8],
    metadata: CiphertextMetadata,
}

impl<'name, 'data> Yct14AbeCiphertext<'name, 'data> {
    pub fn get_public(&self, attribute: &'data str) -> Result<Gt, RabeError> {
        let res: Option<Gt> = self.attributes
            .clone()
            .into_iter()
            .filter(|a| a.name == attribute)
            .map(|a| match a.node.unwrap().public() {
                Ok(node_value) => node_value,
                Err(_) => panic!("no public node value")
            } )
            .nth(0);
        res.ok_or(RabeError::new("no private key found for attribute"))
    }
}

/// The setup algorithm of KP-ABE. Generates a new Yct14AbePublicKey and a new Yct14AbeMasterKey.
// pub fn setup(attribute_keys: Vec<String>) -> (Yct14AbePublicKey, Yct14AbeMasterKey) {
//     // random number generator
//     let mut _rng = rand::thread_rng();
//     // attribute vec
//     let mut private: Vec<Yct14Attribute> = Vec::new();
//     let mut public: Vec<Yct14Attribute> = Vec::new();
//     // generate random values
//     let s: Fr = _rng.gen();
//     let g: Gt = _rng.gen();
//     // generate randomized attributes
//     for attribute in attribute_keys {
//         let attribute_pair = Yct14Attribute::new(attribute, g);
//         public.push(attribute_pair.0);
//         private.push(attribute_pair.1);
//     }
//     return (
//         Yct14AbePublicKey {
//             g: g.pow(s),
//             attributes: public
//         },
//         Yct14AbeMasterKey {
//             s,
//             attributes: private
//         }
//     );
// }

/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_msk` - A Master Key (MSK), generated by the function setup()
///	* `_policy` - An access policy given as PolicyLanguage
///
// pub fn keygen(
//     _pk: &Yct14AbePublicKey,
//     _msk: &Yct14AbeMasterKey,
//     _policy: &String,
//     _language: PolicyLanguage,
// ) -> Result<Yct14AbeSecretKey, RabeError> {
//     match parse(_policy, _language) {
//         Ok(pol) => {
//             let mut du: Vec<Yct14Attribute> = Vec::new();
//             match gen_shares_policy(_msk.s, &pol, None) {
//                 Some(shares) => {
//                     for share in shares.into_iter() {
//                         //println!("share {}", serde_json::to_string(&share.clone()).unwrap());
//                         match Yct14Attribute::private_from(share, _msk) {
//                             Ok(attribute) => du.push(attribute),
//                             Err(e) => {
//                                 println!("Yct14Attribute::Private_from : {} ", e);
//                             }
//                         }
//                     }
//                     Ok(Yct14AbeSecretKey {
//                         policy: (_policy.clone(), _language),
//                         du
//                     })
//                 },
//                 None => Err(RabeError::new("could not generate shares during keygen()"))
//             }
//         },
//         Err(e) => Err(e)
//     }
// }

/// # Arguments
///
///	* `pk` - A Public Key (PK), generated by the function setup()
///	* `_attributes` - A set of attributes given as String Vector
///	* `_plaintext` - plaintext data given as a vec<u8>
///
pub fn encrypt<'attname, 'attlist, 'data>(
    pk: &Yct14AbePublicKey,
    _attributes: &'attlist [&'attname str],
    _plaintext: &'data mut [u8],
    _rng: &mut dyn RngCore,
) -> Result<Yct14AbeCiphertext<'attname, 'data>, RabeError<'static>> {
    if _attributes.is_empty() {
        return Err(RabeError::new("attributes empty"));
    } 
    else if _plaintext.is_empty() {
        return Err(RabeError::new("plaintext empty"));
    }
    else {
        // attribute vector
        let mut attributes: Vec<Yct14Attribute, S> = Vec::new();
        // random secret
        let k: Fr = _rng.gen();
        // aes secret = public g ** random k
        let _cs: Gt = pk.g.pow(k);

        for attr in _attributes.into_iter() {
            attributes.push(Yct14Attribute::public_from(attr, pk, k)).expect("too many attributes for limited-capacity vector");
        }
        //Encrypt plaintext using aes secret
        match encrypt_symmetric(&_cs, _plaintext, _rng) {
            Ok(metadata) => Ok(Yct14AbeCiphertext { attributes, ct: _plaintext, metadata }),
            Err(e) => Err(e)
        }
    }
}

/// # Arguments
///
///	* `_sk` - A Secret Key (SK), generated by keygen()
///	* `_ct` - A Ciphertext (CT), generated by encrypt()
///
// pub fn decrypt(_sk: &Yct14AbeSecretKey, _ct: &Yct14AbeCiphertext) -> Result<Vec<u8>, RabeError> {
//     let _attrs_str = _ct
//         .attributes
//         .iter()
//         .map(|value| value.name.clone())
//         .collect::<Vec<String>>();
//     match parse(_sk.policy.0.as_ref(), _sk.policy.1) {
//         Ok(pol) => {
//             return match calc_pruned(&_attrs_str, &pol, None) {
//                 Err(e) => Err(e),
//                 Ok(_p) => {
//                     let (_match, _list) = _p;
//                     if _match {
//                         let mut _prod_t = Gt::one();
//                         let _coeffs: Vec<(String, Fr)> = calc_coefficients(&pol, Some(Fr::one()), None).unwrap();
//                         for _attr in _list.into_iter() {
//                             let z = _ct.get_public(&_attr).unwrap().pow(_sk.get_private(&_attr).unwrap());
//                             let coeff = _coeffs
//                                 .clone()
//                                 .into_iter()
//                                 .filter(|a| a.0 == _attr)
//                                 .map(|a| a.1 )
//                                 .nth(0)
//                                 .unwrap();
//                             _prod_t = _prod_t * z.pow(coeff);
//                         }
//                         decrypt_symmetric(&_prod_t, &_ct.ct)
//                     } else {
//                         Err(RabeError::new("Error in decrypt: attributes do not match policy."))
//                     }
//                 }
//             }
//         },
//         Err(e)=> Err(e)
//     }
// }

#[cfg(test)]
mod tests {

    use super::*;

    // #[test]
    // fn or() {
    //     // a set of attributes
    //     let mut attributes: Vec<String> = Vec::new();
    //     attributes.push(String::from("A"));
    //     attributes.push(String::from("B"));
    //     attributes.push(String::from("C"));
    //     // setup scheme
    //     let (pk, msk) = setup(attributes.clone());
    //     // println!("pk attrs: {:?}", serde_json::to_string(&pk).unwrap());
    //     // println!("msk attrs: {:?}", serde_json::to_string(&msk).unwrap());
    //     // println!("pk attrs: {:?}", serde_cbor::to_vec(&pk).unwrap());
    //     // println!("msk attrs: {:?}", serde_cbor::to_vec(&msk).unwrap());
    //     // our plaintext
    //     let plaintext =
    //         String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
    //     // our policy
    //     let policy = String::from(r#"{"name": "or", "children": [{"name": "A"}, {"name": "C"}]}"#);
    //     // kp-abe ciphertext
    //     let ct: Yct14AbeCiphertext = encrypt(&pk, &attributes, &plaintext).unwrap();
    //     //println!("ct: {:?}", serde_json::to_string(&ct).unwrap());
    //     // a kp-abe SK key
    //     let sk: Yct14AbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
    //     //println!("sk: {:?}", serde_json::to_string(&sk).unwrap());
    //     // and now decrypt again with matching sk
    //     assert_eq!(decrypt(&sk, &ct).unwrap(), plaintext);
    // }

    #[test]
    fn or_serialized() {
        // a set of attributes
        let attributes = ["A", "B", "C"];
        // setup scheme
        // let (pk, msk) = setup(attributes.clone());
        // println!("pk attrs: {:?}", serde_json::to_string(&pk.attributes).unwrap());
        // println!("msk attrs: {:?}", serde_json::to_string(&msk.attributes).unwrap());
        // let pk: Yct14AbePublicKey = serde_json::from_str("{\"g\":{\"c0\":{\"c0\":{\"c0\":[10842138449374260664,1720400837052274230,12097202828309989789,243422696428700514],\"c1\":[1304985534651507105,8553688861985130063,17161241602274756763,919018618981822090]},\"c1\":{\"c0\":[16281059503180879012,4949288062039633849,17453615021041607962,3368508241958501435],\"c1\":[7321505230095804140,14636492293917056409,649885065941524071,902866970434941333]},\"c2\":{\"c0\":[6221005861171476447,6834667338681924651,16782077469178800237,1289426267592247658],\"c1\":[15281491240573469944,7071798411089663717,16688948661137580758,2613454487315369244]}},\"c1\":{\"c0\":{\"c0\":[16101801376911867416,13397674989389623762,3417072059706527651,1434258783196756262],\"c1\":[15743302611618416113,13244814194993405246,12408455173054950319,814282626046840655]},\"c1\":{\"c0\":[17524613993304203361,18126736417867475690,9403148168109012986,1152156342362260656],\"c1\":[13689786997336956176,5985159241577323635,11607145670977862441,2445070171291066679]},\"c2\":{\"c0\":[11513239460623753796,7961608555564739475,4740795535801375796,2544912645341324431],\"c1\":[3190063385422806387,11298726934993015659,5094393376374913124,1164504449816686271]}}},\"attributes\":[{\"name\":\"A\",\"node\":{\"Public\":{\"c0\":{\"c0\":{\"c0\":[16261598585183018435,17134790394275359208,6497716498327942359,2048913257924349563],\"c1\":[16528852866507302587,11448997204974120330,3902670418042405983,2257851453986395327]},\"c1\":{\"c0\":[17520097989718684971,14390918254610750734,16540479049653100993,2187288365149989304],\"c1\":[10546796425027165913,16475595636764201294,3956546485565317648,3304355145020161900]},\"c2\":{\"c0\":[13166584986709033741,1988430960897661855,11543047779681721247,2605566734364524892],\"c1\":[399426730115314120,3300488426274010238,9028020448241469464,140932613745634328]}},\"c1\":{\"c0\":{\"c0\":[5889772875392418225,18128169191420882960,12509572941198363853,1624431459215488621],\"c1\":[14443167838924558145,9662900215221928015,10411060498814497138,2956014379219969730]},\"c1\":{\"c0\":[10573351020909132661,8447918931318473368,4445466119220567437,1150325452712687229],\"c1\":[16169673081836441259,5888898723370514545,9634337085687775669,1540734545105396950]},\"c2\":{\"c0\":[11150586217416828821,10066912220814264843,10521173308308466188,1666683792433984223],\"c1\":[13560805894948901765,1461772195836812703,1265731509822384946,859014029597705414]}}}}},{\"name\":\"B\",\"node\":{\"Public\":{\"c0\":{\"c0\":{\"c0\":[11551309437501725710,14335612100654362968,12729127660070849666,1359941960435868277],\"c1\":[13060439651907009673,752970308706730672,11029810238196616592,1657251347373379312]},\"c1\":{\"c0\":[8352581217636097326,12815259059428581250,17596087793410610048,2061644078517895150],\"c1\":[10610002833573559029,9072962283656506148,337989915918648794,305147816280187958]},\"c2\":{\"c0\":[8137184495598640319,5430100287950441303,8466525162259643433,2798122024740911080],\"c1\":[5849485178734456496,11694880884759648448,8117413835921634909,2039547239524040859]}},\"c1\":{\"c0\":{\"c0\":[5579352588688777779,16138956296774501324,11594101554276004038,1871566815247106222],\"c1\":[17591680634066683804,7607451595498553514,6759133299801711708,2064182076900068647]},\"c1\":{\"c0\":[4017849169119286797,15115306933676601813,14802806550440548832,1260605561418436158],\"c1\":[6351057382188297738,3540750417166520765,13600897581513304500,2129337414952057210]},\"c2\":{\"c0\":[16350644942574050466,13162225422546960610,4354378967611575557,3322308966931691042],\"c1\":[3586748475999083895,16747274986931001920,14535086559816872378,2890777363311912975]}}}}},{\"name\":\"C\",\"node\":{\"Public\":{\"c0\":{\"c0\":{\"c0\":[10044050012476725592,2740711386730423507,5408485473154788061,756509229284132771],\"c1\":[5932747534335612970,15626733326453646712,11344698482500176437,1662617858179407084]},\"c1\":{\"c0\":[1699280314428696379,12984482881923650711,17199478860414022795,2759197442042984846],\"c1\":[13232242576863749909,15376544134309725116,10740377553933989805,2008709456146010525]},\"c2\":{\"c0\":[5960766252520681617,16431053971361557325,11995487486115124895,2405921535930619455],\"c1\":[674164400322322696,12872558730523219752,17865834311456011942,970658241600415137]}},\"c1\":{\"c0\":{\"c0\":[17896008362062204065,8574090553999427339,9532296008182644881,1969587438344060214],\"c1\":[8009339977592587203,3265089837440369574,3459806168104688083,661223938371033462]},\"c1\":{\"c0\":[16679545618077692883,10889808947212598843,13462677463260524809,3331514430850746247],\"c1\":[1979048677024781299,2866772444318038715,7937390366922339153,2186318151242972377]},\"c2\":{\"c0\":[1250971894371473143,16365284840384926759,16917236662204213369,940142578605349517],\"c1\":[15310536474168031523,36157473784371696,14423009279858083710,331096363466884708]}}}}}]}").unwrap();
        // let msk: Yct14AbeMasterKey = serde_json::from_str("{\"s\":[7711616293370442719,320837966875826624,16308954430340197066,1131681339048127874],\"attributes\":[{\"name\":\"A\",\"node\":{\"Private\":[6348180669214718864,7311058768357042340,14482537325059010832,3446592407153002819]}},{\"name\":\"B\",\"node\":{\"Private\":[7604463295997723371,4572804268404642885,16018635747351613027,3328518854513292375]}},{\"name\":\"C\",\"node\":{\"Private\":[6387120840677927911,17700558060087617379,16660942981804909918,2392390523241083945]}}]}").unwrap();
        // let pk: Yct14AbePublicKey = serde_cbor::from_slice(&[162, 97, 103, 162, 98, 99, 48, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 150, 119, 3, 121, 192, 142, 173, 184, 27, 23, 224, 23, 114, 59, 201, 22, 54, 27, 167, 225, 229, 224, 237, 68, 137, 157, 27, 3, 96, 207, 167, 22, 230, 131, 98, 98, 99, 49, 132, 27, 18, 28, 61, 109, 253, 237, 33, 161, 27, 118, 180, 206, 179, 89, 214, 198, 79, 27, 238, 40, 250, 80, 40, 62, 8, 155, 27, 12, 193, 2, 144, 150, 97, 174, 138, 98, 99, 49, 162, 98, 99, 48, 132, 27, 225, 241, 241, 91, 126, 24, 20, 164, 27, 68, 175, 103, 69, 28, 244, 47, 185, 27, 242, 55, 178, 99, 111, 155, 101, 26, 27, 46, 191, 88, 102, 32, 233, 124, 59, 98, 99, 49, 132, 27, 101, 155, 54, 55, 61, 6, 102, 236, 27, 203, 31, 68, 49, 160, 171, 29, 153, 27, 9, 4, 219, 6, 52, 70, 158, 103, 27, 12, 135, 160, 185, 220, 53, 49, 149, 98, 99, 50, 162, 98, 99, 48, 132, 27, 86, 85, 115, 222, 212, 191, 183, 223, 27, 94, 217, 157, 187, 160, 25, 188, 43, 27, 232, 229, 234, 138, 255, 125, 40, 109, 27, 17, 228, 246, 91, 211, 228, 201, 106, 98, 99, 49, 132, 27, 212, 18, 195, 81, 136, 160, 4, 248, 27, 98, 36, 19, 47, 216, 43, 214, 229, 27, 231, 155, 14, 98, 173, 214, 34, 214, 27, 36, 68, 219, 2, 113, 21, 77, 28, 98, 99, 49, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 223, 117, 23, 10, 146, 186, 62, 24, 27, 185, 238, 26, 107, 62, 180, 49, 210, 27, 47, 107, 224, 239, 18, 184, 79, 163, 27, 19, 231, 130, 195, 168, 109, 57, 38, 98, 99, 49, 132, 27, 218, 123, 114, 80, 76, 254, 197, 241, 27, 183, 207, 8, 86, 24, 162, 29, 62, 27, 172, 51, 176, 60, 177, 76, 107, 175, 27, 11, 76, 233, 187, 240, 75, 79, 79, 98, 99, 49, 162, 98, 99, 48, 132, 27, 243, 51, 239, 147, 216, 188, 160, 97, 27, 251, 143, 26, 187, 132, 32, 170, 234, 27, 130, 126, 177, 112, 90, 128, 183, 250, 27, 15, 253, 72, 22, 200, 55, 68, 176, 98, 99, 49, 132, 27, 189, 251, 228, 190, 19, 7, 221, 16, 27, 83, 15, 142, 158, 150, 92, 220, 115, 27, 161, 20, 221, 125, 142, 217, 59, 41, 27, 33, 238, 162, 93, 194, 181, 33, 55, 98, 99, 50, 162, 98, 99, 48, 132, 27, 159, 199, 62, 74, 40, 125, 34, 68, 27, 110, 125, 80, 204, 131, 37, 171, 147, 27, 65, 202, 176, 108, 8, 50, 220, 52, 27, 35, 81, 88, 145, 65, 248, 36, 143, 98, 99, 49, 132, 27, 44, 69, 97, 191, 83, 27, 61, 115, 27, 156, 205, 36, 72, 190, 101, 147, 107, 27, 70, 178, 235, 200, 216, 237, 248, 100, 27, 16, 41, 38, 160, 150, 175, 110, 191, 106, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 131, 162, 100, 110, 97, 109, 101, 97, 65, 100, 110, 111, 100, 101, 161, 102, 80, 117, 98, 108, 105, 99, 162, 98, 99, 48, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 225, 172, 205, 193, 109, 212, 29, 195, 27, 237, 203, 1, 20, 95, 142, 233, 232, 27, 90, 44, 134, 186, 150, 8, 52, 215, 27, 28, 111, 51, 192, 162, 43, 78, 123, 98, 99, 49, 132, 27, 229, 98, 72, 27, 196, 221, 102, 187, 27, 158, 227, 2, 76, 108, 236, 45, 138, 27, 54, 41, 18, 17, 102, 215, 196, 95, 27, 31, 85, 127, 239, 78, 117, 84, 191, 98, 99, 49, 162, 98, 99, 48, 132, 27, 243, 35, 228, 75, 211, 55, 181, 43, 27, 199, 182, 207, 231, 253, 194, 29, 14, 27, 229, 139, 150, 15, 121, 93, 33, 193, 27, 30, 90, 207, 45, 234, 28, 41, 184, 98, 99, 49, 132, 27, 146, 93, 191, 120, 32, 26, 158, 217, 27, 228, 165, 18, 240, 176, 78, 81, 78, 27, 54, 232, 122, 16, 225, 112, 226, 16, 27, 45, 219, 109, 127, 70, 169, 63, 108, 98, 99, 50, 162, 98, 99, 48, 132, 27, 182, 185, 27, 73, 45, 200, 131, 13, 27, 27, 152, 83, 108, 124, 177, 155, 159, 27, 160, 49, 36, 204, 69, 74, 91, 159, 27, 36, 40, 213, 35, 216, 95, 65, 92, 98, 99, 49, 132, 27, 5, 139, 12, 126, 170, 81, 177, 200, 27, 45, 205, 176, 188, 169, 89, 180, 126, 27, 125, 73, 248, 195, 226, 101, 72, 24, 27, 1, 244, 177, 119, 43, 147, 108, 24, 98, 99, 49, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 81, 188, 173, 57, 141, 127, 1, 177, 27, 251, 148, 49, 213, 26, 210, 112, 16, 27, 173, 154, 238, 79, 187, 247, 140, 205, 27, 22, 139, 35, 206, 56, 130, 54, 109, 98, 99, 49, 132, 27, 200, 112, 112, 160, 86, 113, 207, 65, 27, 134, 25, 132, 140, 172, 89, 64, 79, 27, 144, 123, 132, 93, 14, 240, 113, 114, 27, 41, 5, 223, 106, 144, 90, 102, 194, 98, 99, 49, 162, 98, 99, 48, 132, 27, 146, 188, 22, 187, 198, 205, 123, 117, 27, 117, 61, 9, 130, 80, 137, 2, 152, 27, 61, 177, 119, 225, 225, 45, 29, 141, 27, 15, 246, 198, 231, 145, 7, 182, 125, 98, 99, 49, 132, 27, 224, 102, 55, 255, 81, 14, 142, 171, 27, 81, 185, 146, 48, 44, 192, 56, 113, 27, 133, 180, 10, 136, 214, 202, 193, 181, 27, 21, 97, 201, 231, 214, 46, 36, 214, 98, 99, 50, 162, 98, 99, 48, 132, 27, 154, 190, 215, 22, 30, 127, 39, 149, 27, 139, 180, 219, 83, 250, 172, 74, 11, 27, 146, 2, 183, 97, 94, 12, 42, 12, 27, 23, 33, 64, 20, 40, 237, 178, 223, 98, 99, 49, 132, 27, 188, 49, 169, 28, 252, 115, 211, 133, 27, 20, 73, 66, 17, 59, 101, 93, 159, 27, 17, 144, 200, 26, 31, 251, 107, 50, 27, 11, 235, 212, 181, 107, 63, 132, 198, 162, 100, 110, 97, 109, 101, 97, 66, 100, 110, 111, 100, 101, 161, 102, 80, 117, 98, 108, 105, 99, 162, 98, 99, 48, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 160, 78, 126, 187, 96, 232, 92, 14, 27, 198, 242, 83, 64, 145, 75, 113, 88, 27, 176, 166, 242, 42, 63, 31, 76, 130, 27, 18, 223, 124, 1, 250, 237, 162, 117, 98, 99, 49, 132, 27, 181, 64, 0, 170, 142, 87, 252, 137, 27, 10, 115, 22, 129, 160, 225, 130, 176, 27, 153, 17, 193, 249, 35, 173, 13, 144, 27, 22, 255, 189, 81, 231, 186, 78, 240, 98, 99, 49, 162, 98, 99, 48, 132, 27, 115, 234, 84, 93, 18, 204, 157, 46, 27, 177, 216, 242, 55, 101, 216, 223, 130, 27, 244, 49, 220, 158, 186, 211, 147, 128, 27, 28, 156, 110, 93, 201, 88, 191, 238, 98, 99, 49, 132, 27, 147, 62, 77, 92, 233, 10, 58, 245, 27, 125, 233, 163, 32, 89, 220, 235, 36, 27, 4, 176, 200, 9, 171, 254, 197, 218, 27, 4, 60, 26, 82, 121, 93, 228, 54, 98, 99, 50, 162, 98, 99, 48, 132, 27, 112, 237, 22, 47, 163, 249, 28, 191, 27, 75, 91, 151, 113, 38, 8, 75, 87, 27, 117, 127, 35, 199, 10, 100, 124, 41, 27, 38, 212, 237, 40, 10, 224, 247, 232, 98, 99, 49, 132, 27, 81, 45, 139, 199, 53, 97, 46, 176, 27, 162, 76, 144, 51, 218, 154, 216, 192, 27, 112, 166, 216, 224, 56, 243, 54, 93, 27, 28, 77, 237, 104, 138, 117, 128, 155, 98, 99, 49, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 77, 109, 215, 158, 101, 115, 98, 51, 27, 223, 249, 23, 62, 122, 204, 67, 204, 27, 160, 230, 133, 239, 120, 108, 240, 198, 27, 25, 249, 36, 26, 60, 54, 128, 174, 98, 99, 49, 132, 27, 244, 34, 52, 84, 251, 169, 199, 156, 27, 105, 147, 24, 235, 139, 171, 128, 170, 27, 93, 205, 67, 236, 188, 49, 228, 92, 27, 28, 165, 114, 169, 149, 91, 77, 39, 98, 99, 49, 162, 98, 99, 48, 132, 27, 55, 194, 68, 136, 38, 116, 22, 13, 27, 209, 196, 91, 146, 100, 202, 241, 213, 27, 205, 110, 34, 33, 5, 213, 153, 224, 27, 17, 126, 146, 20, 66, 58, 78, 62, 98, 99, 49, 132, 27, 88, 35, 125, 10, 45, 116, 174, 10, 27, 49, 35, 69, 190, 165, 134, 209, 189, 27, 188, 192, 24, 74, 44, 145, 233, 180, 27, 29, 140, 237, 24, 225, 42, 121, 122, 98, 99, 50, 162, 98, 99, 48, 132, 27, 226, 233, 40, 242, 34, 169, 220, 162, 27, 182, 169, 158, 73, 12, 135, 0, 226, 27, 60, 109, 220, 153, 189, 235, 141, 5, 27, 46, 27, 54, 103, 48, 14, 246, 34, 98, 99, 49, 132, 27, 49, 198, 176, 188, 74, 153, 93, 119, 27, 232, 106, 69, 222, 167, 206, 154, 64, 27, 201, 183, 0, 55, 73, 112, 113, 186, 27, 40, 30, 26, 178, 40, 242, 104, 15, 162, 100, 110, 97, 109, 101, 97, 67, 100, 110, 111, 100, 101, 161, 102, 80, 117, 98, 108, 105, 99, 162, 98, 99, 48, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 139, 99, 162, 69, 75, 238, 217, 88, 27, 38, 8, 246, 124, 61, 239, 100, 211, 27, 75, 14, 204, 225, 232, 64, 106, 221, 27, 10, 127, 169, 34, 200, 201, 7, 163, 98, 99, 49, 132, 27, 82, 85, 90, 115, 14, 38, 24, 42, 27, 216, 221, 79, 42, 155, 7, 37, 120, 27, 157, 112, 119, 41, 189, 86, 10, 53, 27, 23, 18, 206, 34, 18, 1, 28, 236, 98, 99, 49, 162, 98, 99, 48, 132, 27, 23, 149, 14, 113, 91, 86, 39, 59, 27, 180, 50, 38, 98, 233, 51, 20, 151, 27, 238, 176, 210, 229, 148, 209, 116, 139, 27, 38, 74, 163, 116, 102, 35, 121, 142, 98, 99, 49, 132, 27, 183, 162, 94, 132, 39, 195, 103, 21, 27, 213, 100, 117, 107, 246, 165, 195, 188, 27, 149, 13, 124, 122, 247, 208, 119, 173, 27, 27, 224, 94, 155, 150, 141, 17, 157, 98, 99, 50, 162, 98, 99, 48, 132, 27, 82, 184, 229, 83, 62, 161, 176, 145, 27, 228, 6, 212, 136, 16, 70, 235, 77, 27, 166, 120, 136, 80, 85, 137, 22, 159, 27, 33, 99, 140, 227, 202, 155, 86, 63, 98, 99, 49, 132, 27, 9, 91, 28, 243, 65, 109, 33, 8, 27, 178, 164, 131, 246, 179, 48, 151, 40, 27, 247, 240, 49, 166, 38, 82, 54, 166, 27, 13, 120, 120, 135, 40, 229, 229, 161, 98, 99, 49, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 248, 91, 100, 201, 198, 35, 76, 161, 27, 118, 253, 73, 238, 111, 43, 7, 11, 27, 132, 73, 132, 183, 21, 153, 192, 145, 27, 27, 85, 97, 87, 0, 145, 189, 54, 98, 99, 49, 132, 27, 111, 38, 228, 70, 57, 189, 195, 195, 27, 45, 79, 237, 232, 112, 95, 3, 166, 27, 48, 3, 179, 97, 9, 149, 217, 211, 27, 9, 45, 35, 171, 43, 151, 25, 118, 98, 99, 49, 162, 98, 99, 48, 132, 27, 231, 121, 166, 94, 28, 113, 179, 211, 27, 151, 32, 95, 138, 114, 122, 62, 59, 27, 186, 213, 9, 211, 19, 76, 241, 9, 27, 46, 59, 234, 185, 70, 242, 71, 135, 98, 99, 49, 132, 27, 27, 118, 254, 73, 75, 68, 211, 243, 27, 39, 200, 210, 89, 107, 116, 122, 187, 27, 110, 39, 70, 124, 16, 3, 115, 81, 27, 30, 87, 92, 198, 98, 211, 124, 217, 98, 99, 50, 162, 98, 99, 48, 132, 27, 17, 92, 88, 79, 92, 2, 86, 247, 27, 227, 29, 43, 218, 247, 58, 148, 39, 27, 234, 198, 25, 28, 231, 229, 168, 121, 27, 13, 12, 14, 177, 179, 253, 218, 141, 98, 99, 49, 132, 27, 212, 121, 243, 205, 247, 114, 121, 35, 27, 0, 128, 117, 7, 228, 228, 153, 240, 27, 200, 40, 210, 134, 14, 26, 135, 126, 27, 4, 152, 74, 99, 106, 222, 6, 100]).unwrap();
        
        // println!("g: {:?}", serde_cbor::to_vec(&pk.g).unwrap());
        // for att in &pk.attributes {
        //     println!("{}: {:?}", att.name, serde_cbor::to_vec(att).unwrap());
        // }

        let g = serde_cbor::from_slice(&[162, 98, 99, 48, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 150, 119, 3, 121, 192, 142, 173, 184, 27, 23, 224, 23, 114, 59, 201, 22, 54, 27, 167, 225, 229, 224, 237, 68, 137, 157, 27, 3, 96, 207, 167, 22, 230, 131, 98, 98, 99, 49, 132, 27, 18, 28, 61, 109, 253, 237, 33, 161, 27, 118, 180, 206, 179, 89, 214, 198, 79, 27, 238, 40, 250, 80, 40, 62, 8, 155, 27, 12, 193, 2, 144, 150, 97, 174, 138, 98, 99, 49, 162, 98, 99, 48, 132, 27, 225, 241, 241, 91, 126, 24, 20, 164, 27, 68, 175, 103, 69, 28, 244, 47, 185, 27, 242, 55, 178, 99, 111, 155, 101, 26, 27, 46, 191, 88, 102, 32, 233, 124, 59, 98, 99, 49, 132, 27, 101, 155, 54, 55, 61, 6, 102, 236, 27, 203, 31, 68, 49, 160, 171, 29, 153, 27, 9, 4, 219, 6, 52, 70, 158, 103, 27, 12, 135, 160, 185, 220, 53, 49, 149, 98, 99, 50, 162, 98, 99, 48, 132, 27, 86, 85, 115, 222, 212, 191, 183, 223, 27, 94, 217, 157, 187, 160, 25, 188, 43, 27, 232, 229, 234, 138, 255, 125, 40, 109, 27, 17, 228, 246, 91, 211, 228, 201, 106, 98, 99, 49, 132, 27, 212, 18, 195, 81, 136, 160, 4, 248, 27, 98, 36, 19, 47, 216, 43, 214, 229, 27, 231, 155, 14, 98, 173, 214, 34, 214, 27, 36, 68, 219, 2, 113, 21, 77, 28, 98, 99, 49, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 223, 117, 23, 10, 146, 186, 62, 24, 27, 185, 238, 26, 107, 62, 180, 49, 210, 27, 47, 107, 224, 239, 18, 184, 79, 163, 27, 19, 231, 130, 195, 168, 109, 57, 38, 98, 99, 49, 132, 27, 218, 123, 114, 80, 76, 254, 197, 241, 27, 183, 207, 8, 86, 24, 162, 29, 62, 27, 172, 51, 176, 60, 177, 76, 107, 175, 27, 11, 76, 233, 187, 240, 75, 79, 79, 98, 99, 49, 162, 98, 99, 48, 132, 27, 243, 51, 239, 147, 216, 188, 160, 97, 27, 251, 143, 26, 187, 132, 32, 170, 234, 27, 130, 126, 177, 112, 90, 128, 183, 250, 27, 15, 253, 72, 22, 200, 55, 68, 176, 98, 99, 49, 132, 27, 189, 251, 228, 190, 19, 7, 221, 16, 27, 83, 15, 142, 158, 150, 92, 220, 115, 27, 161, 20, 221, 125, 142, 217, 59, 41, 27, 33, 238, 162, 93, 194, 181, 33, 55, 98, 99, 50, 162, 98, 99, 48, 132, 27, 159, 199, 62, 74, 40, 125, 34, 68, 27, 110, 125, 80, 204, 131, 37, 171, 147, 27, 65, 202, 176, 108, 8, 50, 220, 52, 27, 35, 81, 88, 145, 65, 248, 36, 143, 98, 99, 49, 132, 27, 44, 69, 97, 191, 83, 27, 61, 115, 27, 156, 205, 36, 72, 190, 101, 147, 107, 27, 70, 178, 235, 200, 216, 237, 248, 100, 27, 16, 41, 38, 160, 150, 175, 110, 191]).unwrap();
        let a = serde_cbor::from_slice(&[162, 100, 110, 97, 109, 101, 97, 65, 100, 110, 111, 100, 101, 161, 102, 80, 117, 98, 108, 105, 99, 162, 98, 99, 48, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 225, 172, 205, 193, 109, 212, 29, 195, 27, 237, 203, 1, 20, 95, 142, 233, 232, 27, 90, 44, 134, 186, 150, 8, 52, 215, 27, 28, 111, 51, 192, 162, 43, 78, 123, 98, 99, 49, 132, 27, 229, 98, 72, 27, 196, 221, 102, 187, 27, 158, 227, 2, 76, 108, 236, 45, 138, 27, 54, 41, 18, 17, 102, 215, 196, 95, 27, 31, 85, 127, 239, 78, 117, 84, 191, 98, 99, 49, 162, 98, 99, 48, 132, 27, 243, 35, 228, 75, 211, 55, 181, 43, 27, 199, 182, 207, 231, 253, 194, 29, 14, 27, 229, 139, 150, 15, 121, 93, 33, 193, 27, 30, 90, 207, 45, 234, 28, 41, 184, 98, 99, 49, 132, 27, 146, 93, 191, 120, 32, 26, 158, 217, 27, 228, 165, 18, 240, 176, 78, 81, 78, 27, 54, 232, 122, 16, 225, 112, 226, 16, 27, 45, 219, 109, 127, 70, 169, 63, 108, 98, 99, 50, 162, 98, 99, 48, 132, 27, 182, 185, 27, 73, 45, 200, 131, 13, 27, 27, 152, 83, 108, 124, 177, 155, 159, 27, 160, 49, 36, 204, 69, 74, 91, 159, 27, 36, 40, 213, 35, 216, 95, 65, 92, 98, 99, 49, 132, 27, 5, 139, 12, 126, 170, 81, 177, 200, 27, 45, 205, 176, 188, 169, 89, 180, 126, 27, 125, 73, 248, 195, 226, 101, 72, 24, 27, 1, 244, 177, 119, 43, 147, 108, 24, 98, 99, 49, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 81, 188, 173, 57, 141, 127, 1, 177, 27, 251, 148, 49, 213, 26, 210, 112, 16, 27, 173, 154, 238, 79, 187, 247, 140, 205, 27, 22, 139, 35, 206, 56, 130, 54, 109, 98, 99, 49, 132, 27, 200, 112, 112, 160, 86, 113, 207, 65, 27, 134, 25, 132, 140, 172, 89, 64, 79, 27, 144, 123, 132, 93, 14, 240, 113, 114, 27, 41, 5, 223, 106, 144, 90, 102, 194, 98, 99, 49, 162, 98, 99, 48, 132, 27, 146, 188, 22, 187, 198, 205, 123, 117, 27, 117, 61, 9, 130, 80, 137, 2, 152, 27, 61, 177, 119, 225, 225, 45, 29, 141, 27, 15, 246, 198, 231, 145, 7, 182, 125, 98, 99, 49, 132, 27, 224, 102, 55, 255, 81, 14, 142, 171, 27, 81, 185, 146, 48, 44, 192, 56, 113, 27, 133, 180, 10, 136, 214, 202, 193, 181, 27, 21, 97, 201, 231, 214, 46, 36, 214, 98, 99, 50, 162, 98, 99, 48, 132, 27, 154, 190, 215, 22, 30, 127, 39, 149, 27, 139, 180, 219, 83, 250, 172, 74, 11, 27, 146, 2, 183, 97, 94, 12, 42, 12, 27, 23, 33, 64, 20, 40, 237, 178, 223, 98, 99, 49, 132, 27, 188, 49, 169, 28, 252, 115, 211, 133, 27, 20, 73, 66, 17, 59, 101, 93, 159, 27, 17, 144, 200, 26, 31, 251, 107, 50, 27, 11, 235, 212, 181, 107, 63, 132, 198]).unwrap();
        let b = serde_cbor::from_slice(&[162, 100, 110, 97, 109, 101, 97, 66, 100, 110, 111, 100, 101, 161, 102, 80, 117, 98, 108, 105, 99, 162, 98, 99, 48, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 160, 78, 126, 187, 96, 232, 92, 14, 27, 198, 242, 83, 64, 145, 75, 113, 88, 27, 176, 166, 242, 42, 63, 31, 76, 130, 27, 18, 223, 124, 1, 250, 237, 162, 117, 98, 99, 49, 132, 27, 181, 64, 0, 170, 142, 87, 252, 137, 27, 10, 115, 22, 129, 160, 225, 130, 176, 27, 153, 17, 193, 249, 35, 173, 13, 144, 27, 22, 255, 189, 81, 231, 186, 78, 240, 98, 99, 49, 162, 98, 99, 48, 132, 27, 115, 234, 84, 93, 18, 204, 157, 46, 27, 177, 216, 242, 55, 101, 216, 223, 130, 27, 244, 49, 220, 158, 186, 211, 147, 128, 27, 28, 156, 110, 93, 201, 88, 191, 238, 98, 99, 49, 132, 27, 147, 62, 77, 92, 233, 10, 58, 245, 27, 125, 233, 163, 32, 89, 220, 235, 36, 27, 4, 176, 200, 9, 171, 254, 197, 218, 27, 4, 60, 26, 82, 121, 93, 228, 54, 98, 99, 50, 162, 98, 99, 48, 132, 27, 112, 237, 22, 47, 163, 249, 28, 191, 27, 75, 91, 151, 113, 38, 8, 75, 87, 27, 117, 127, 35, 199, 10, 100, 124, 41, 27, 38, 212, 237, 40, 10, 224, 247, 232, 98, 99, 49, 132, 27, 81, 45, 139, 199, 53, 97, 46, 176, 27, 162, 76, 144, 51, 218, 154, 216, 192, 27, 112, 166, 216, 224, 56, 243, 54, 93, 27, 28, 77, 237, 104, 138, 117, 128, 155, 98, 99, 49, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 77, 109, 215, 158, 101, 115, 98, 51, 27, 223, 249, 23, 62, 122, 204, 67, 204, 27, 160, 230, 133, 239, 120, 108, 240, 198, 27, 25, 249, 36, 26, 60, 54, 128, 174, 98, 99, 49, 132, 27, 244, 34, 52, 84, 251, 169, 199, 156, 27, 105, 147, 24, 235, 139, 171, 128, 170, 27, 93, 205, 67, 236, 188, 49, 228, 92, 27, 28, 165, 114, 169, 149, 91, 77, 39, 98, 99, 49, 162, 98, 99, 48, 132, 27, 55, 194, 68, 136, 38, 116, 22, 13, 27, 209, 196, 91, 146, 100, 202, 241, 213, 27, 205, 110, 34, 33, 5, 213, 153, 224, 27, 17, 126, 146, 20, 66, 58, 78, 62, 98, 99, 49, 132, 27, 88, 35, 125, 10, 45, 116, 174, 10, 27, 49, 35, 69, 190, 165, 134, 209, 189, 27, 188, 192, 24, 74, 44, 145, 233, 180, 27, 29, 140, 237, 24, 225, 42, 121, 122, 98, 99, 50, 162, 98, 99, 48, 132, 27, 226, 233, 40, 242, 34, 169, 220, 162, 27, 182, 169, 158, 73, 12, 135, 0, 226, 27, 60, 109, 220, 153, 189, 235, 141, 5, 27, 46, 27, 54, 103, 48, 14, 246, 34, 98, 99, 49, 132, 27, 49, 198, 176, 188, 74, 153, 93, 119, 27, 232, 106, 69, 222, 167, 206, 154, 64, 27, 201, 183, 0, 55, 73, 112, 113, 186, 27, 40, 30, 26, 178, 40, 242, 104, 15]).unwrap();
        let c = serde_cbor::from_slice(&[162, 100, 110, 97, 109, 101, 97, 67, 100, 110, 111, 100, 101, 161, 102, 80, 117, 98, 108, 105, 99, 162, 98, 99, 48, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 139, 99, 162, 69, 75, 238, 217, 88, 27, 38, 8, 246, 124, 61, 239, 100, 211, 27, 75, 14, 204, 225, 232, 64, 106, 221, 27, 10, 127, 169, 34, 200, 201, 7, 163, 98, 99, 49, 132, 27, 82, 85, 90, 115, 14, 38, 24, 42, 27, 216, 221, 79, 42, 155, 7, 37, 120, 27, 157, 112, 119, 41, 189, 86, 10, 53, 27, 23, 18, 206, 34, 18, 1, 28, 236, 98, 99, 49, 162, 98, 99, 48, 132, 27, 23, 149, 14, 113, 91, 86, 39, 59, 27, 180, 50, 38, 98, 233, 51, 20, 151, 27, 238, 176, 210, 229, 148, 209, 116, 139, 27, 38, 74, 163, 116, 102, 35, 121, 142, 98, 99, 49, 132, 27, 183, 162, 94, 132, 39, 195, 103, 21, 27, 213, 100, 117, 107, 246, 165, 195, 188, 27, 149, 13, 124, 122, 247, 208, 119, 173, 27, 27, 224, 94, 155, 150, 141, 17, 157, 98, 99, 50, 162, 98, 99, 48, 132, 27, 82, 184, 229, 83, 62, 161, 176, 145, 27, 228, 6, 212, 136, 16, 70, 235, 77, 27, 166, 120, 136, 80, 85, 137, 22, 159, 27, 33, 99, 140, 227, 202, 155, 86, 63, 98, 99, 49, 132, 27, 9, 91, 28, 243, 65, 109, 33, 8, 27, 178, 164, 131, 246, 179, 48, 151, 40, 27, 247, 240, 49, 166, 38, 82, 54, 166, 27, 13, 120, 120, 135, 40, 229, 229, 161, 98, 99, 49, 163, 98, 99, 48, 162, 98, 99, 48, 132, 27, 248, 91, 100, 201, 198, 35, 76, 161, 27, 118, 253, 73, 238, 111, 43, 7, 11, 27, 132, 73, 132, 183, 21, 153, 192, 145, 27, 27, 85, 97, 87, 0, 145, 189, 54, 98, 99, 49, 132, 27, 111, 38, 228, 70, 57, 189, 195, 195, 27, 45, 79, 237, 232, 112, 95, 3, 166, 27, 48, 3, 179, 97, 9, 149, 217, 211, 27, 9, 45, 35, 171, 43, 151, 25, 118, 98, 99, 49, 162, 98, 99, 48, 132, 27, 231, 121, 166, 94, 28, 113, 179, 211, 27, 151, 32, 95, 138, 114, 122, 62, 59, 27, 186, 213, 9, 211, 19, 76, 241, 9, 27, 46, 59, 234, 185, 70, 242, 71, 135, 98, 99, 49, 132, 27, 27, 118, 254, 73, 75, 68, 211, 243, 27, 39, 200, 210, 89, 107, 116, 122, 187, 27, 110, 39, 70, 124, 16, 3, 115, 81, 27, 30, 87, 92, 198, 98, 211, 124, 217, 98, 99, 50, 162, 98, 99, 48, 132, 27, 17, 92, 88, 79, 92, 2, 86, 247, 27, 227, 29, 43, 218, 247, 58, 148, 39, 27, 234, 198, 25, 28, 231, 229, 168, 121, 27, 13, 12, 14, 177, 179, 253, 218, 141, 98, 99, 49, 132, 27, 212, 121, 243, 205, 247, 114, 121, 35, 27, 0, 128, 117, 7, 228, 228, 153, 240, 27, 200, 40, 210, 134, 14, 26, 135, 126, 27, 4, 152, 74, 99, 106, 222, 6, 100]).unwrap();

        let pk = Yct14AbePublicKey { g, attributes: &[a, b, c]};
        // println!("pk attrs cbor: {:?}", serde_cbor::to_vec(&pk).unwrap());
        // our plaintext
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        // let policy = String::from(r#"{"name": "or", "children": [{"name": "A"}, {"name": "C"}]}"#);
        // kp-abe ciphertext
        let ct: Yct14AbeCiphertext = encrypt(&pk, &attributes, &plaintext).unwrap();
        // let ct_json = serde_json::to_string(&ct).unwrap();

        // let ct2: Yct14AbeCiphertext = serde_json::from_str(&ct_json).unwrap();

        // println!("{}", serde_json::to_string_pretty(&ct2).unwrap());

        //println!("ct: {:?}", serde_json::to_string(&ct).unwrap());
        // a kp-abe SK key
        // let sk: Yct14AbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // //println!("sk: {:?}", serde_json::to_string(&sk).unwrap());
        // // and now decrypt again with matching sk
        // assert_eq!(decrypt(&sk, &ct).unwrap(), plaintext);
    }

}
