use ccatoken::store::{
    Cpak, MemoRefValueStore, MemoTrustAnchorStore, PlatformRefValue, RealmRefValue, RefValues,
    SwComponent,
};
use ccatoken::token;
use clap::Parser;
use ear::TrustVector;
use serde_json::value::RawValue;
use std::error::Error;
use std::fs;

#[derive(Parser)]
enum CCATokenCli {
    Appraise(AppraiseArgs),
    Verify(VerifyArgs),
    Golden(GoldenArgs),
}

#[derive(Debug, clap::Args)]
#[command(author, version, long_about = None,
    about = "Cryptographically verify the supplied CCA token using a matching \
    CPAK from the trust anchor store")]
struct VerifyArgs {
    #[arg(short, long, default_value = "token.cbor")]
    evidence: String,

    #[arg(short, long, default_value = "tastore.json")]
    tastore: String,
}

#[derive(Debug, clap::Args)]
#[command(author, version, long_about = None,
    about = "Appraise the supplied CCA token using reference values found in \
    the reference value store")]
struct AppraiseArgs {
    #[arg(short, long, default_value = "token.cbor")]
    evidence: String,

    #[arg(short, long, default_value = "rvstore.json")]
    rvstore: String,
}

#[derive(Debug, clap::Args)]
#[command(author, version, long_about = None,
    about = "Extract golden values from the supplied CCA token after \
    successful verification using CPAK")]
struct GoldenArgs {
    #[arg(short, long, default_value = "token.cbor")]
    evidence: String,

    #[arg(short, long, default_value = "cpak.json")]
    cpak: String,

    #[arg(short, long, default_value = "tastore.json")]
    tastore: String,

    #[arg(short, long, default_value = "rvstore.json")]
    rvstore: String,
}

fn main() {
    match CCATokenCli::parse() {
        CCATokenCli::Appraise(args) => match appraise(&args) {
            Ok((_, _)) => println!("appraisal successful"),
            Err(e) => eprintln!("appraisal failed: {e}"),
        },

        CCATokenCli::Verify(args) => match verify(&args) {
            Ok((_, _)) => println!("verification successful"),
            Err(e) => eprintln!("verification failed: {e}"),
        },

        CCATokenCli::Golden(args) => match golden(&args) {
            Ok(_) => println!("golden values extraction successful"),
            Err(e) => eprintln!("golden values extraction failed: {e}"),
        },
    }
}

fn appraise(args: &AppraiseArgs) -> Result<(TrustVector, TrustVector), Box<dyn Error>> {
    let j = fs::read_to_string(&args.rvstore)?;

    let mut rvs: MemoRefValueStore = Default::default();
    rvs.load_json(&j)?;

    let c: Vec<u8> = fs::read(&args.evidence)?;

    let mut e: token::Evidence = token::Evidence::decode(&c)?;

    e.appraise(&rvs)?;

    Ok(e.get_trust_vectors())
}

fn verify(args: &VerifyArgs) -> Result<(TrustVector, TrustVector), Box<dyn Error>> {
    let j = fs::read_to_string(&args.tastore)?;

    let mut tas: MemoTrustAnchorStore = Default::default();
    tas.load_json(&j)?;

    let c: Vec<u8> = fs::read(&args.evidence)?;

    let mut e: token::Evidence = token::Evidence::decode(&c)?;

    todo!("verify with args: {:#?}", args);

    Ok(e.get_trust_vectors())
}

fn golden(args: &GoldenArgs) -> Result<(), Box<dyn Error>> {
    let c: Vec<u8> = fs::read(&args.evidence)?;

    let mut e: token::Evidence = token::Evidence::decode(&c)?;

    let j = fs::read_to_string(&args.cpak)?;

    // TODO verify using CPAK

    let rv = map_evidence_to_refval(&e)?;
    fs::write(&args.rvstore, rv)?;

    let ta = map_evidence_to_trustanchor(&e.platform_claims, &j)?;
    fs::write(&args.tastore, ta)?;

    Ok(())
}

fn map_evidence_to_refval(e: &token::Evidence) -> Result<String, Box<dyn Error>> {
    let prv = map_evidence_to_platform_refval(&e.platform_claims)?;
    let rrv = map_evidence_to_realm_refval(&e.realm_claims)?;

    let rvs: RefValues = RefValues {
        platform: Some(vec![prv]),
        realm: Some(vec![rrv]),
    };

    let j = serde_json::to_string_pretty(&rvs)?;

    Ok(j)
}

fn map_evidence_to_platform_refval(
    p: &token::Platform,
) -> Result<PlatformRefValue, Box<dyn Error>> {
    let mut v = PlatformRefValue {
        impl_id: p.impl_id,
        config: p.config.clone(),
        ..Default::default()
    };

    for other in &p.sw_components {
        let swc = SwComponent {
            mval: other.mval.clone(),
            signer_id: other.signer_id.clone(),
            version: other.version.clone(),
            mtyp: other.mtyp.clone(),
        };

        v.sw_components.push(swc)
    }

    Ok(v)
}

fn map_evidence_to_realm_refval(p: &token::Realm) -> Result<RealmRefValue, Box<dyn Error>> {
    let mut v = RealmRefValue {
        perso: p.perso.to_vec(),
        rim: p.rim.clone(),
        rak_hash_alg: p.rak_hash_alg.clone(),
        ..Default::default()
    };

    for (i, other) in p.rem.iter().enumerate() {
        v.rem[i].value = other.clone();
    }

    Ok(v)
}

fn map_evidence_to_trustanchor(p: &token::Platform, cpak: &str) -> Result<String, Box<dyn Error>> {
    let raw_pkey = RawValue::from_string(cpak.to_string())?;

    let v = Cpak {
        raw_pkey,
        inst_id: p.inst_id,
        impl_id: p.impl_id,
        ..Default::default() // pkey is not serialised
    };

    let j = serde_json::to_string_pretty(&vec![v])?;

    Ok(j)
}
