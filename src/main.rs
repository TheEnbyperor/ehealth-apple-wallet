#![feature(decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate include_dir;

use coset::TaggedCborSerializable;
use chrono::prelude::*;
use serde::Deserializer;
use std::fmt::Formatter;
use std::io::Write;

const VALUE_SET_COUNTRY_CODE_STR: &'static str = include_str!("../eu-dcc-valuesets/country-2-codes.json");
const VALUE_SET_DISEASE_STR: &'static str = include_str!("../eu-dcc-valuesets/disease-agent-targeted.json");
const VALUE_SET_TEST_MANUFACTURER_STR: &'static str = include_str!("../eu-dcc-valuesets/test-manf.json");
const VALUE_SET_TEST_RESULT_STR: &'static str = include_str!("../eu-dcc-valuesets/test-result.json");
const VALUE_SET_TEST_TYPE_STR: &'static str = include_str!("../eu-dcc-valuesets/test-type.json");
const VALUE_SET_VACCINE_MANUFACTURER_STR: &'static str = include_str!("../eu-dcc-valuesets/vaccine-mah-manf.json");
const VALUE_SET_VACCINE_PRODUCT_STR: &'static str = include_str!("../eu-dcc-valuesets/vaccine-medicinal-product.json");
const VALUE_SET_VACCINE_PROPHYLAXIS_STR: &'static str = include_str!("../eu-dcc-valuesets/vaccine-prophylaxis.json");

const UK_CERT_URL: &'static str = "https://covid-status.service.nhsx.nhs.uk/pubkeys/keys.json";

const PASS_TYPE_ID: &'static str = "pass.ch.magicalcodewit.pass.covid";
const PASS_TEAM_ID: &'static str = "MQ9TN9772U";

const PASS_ASSETS: include_dir::Dir = include_dir!("./pass-assets");

const VERIFIABLE_COUNTRIES: [&'static str; 1] = ["GB"];

#[derive(Debug, Deserialize)]
struct ValueSet {
    #[serde(rename = "valueSetId")]
    id: String,
    #[serde(rename = "valueSetDate")]
    date: String,
    #[serde(rename = "valueSetValues")]
    values: std::collections::HashMap<String, ValueSetValue>,
}

#[derive(Debug, Deserialize, Clone)]
struct ValueSetValue {
    display: String,
    lang: String,
    active: bool,
    version: String,
    system: String,
}

lazy_static! {
    static ref VALUE_SET_COUNTRY_CODE: ValueSet = serde_json::from_str(VALUE_SET_COUNTRY_CODE_STR).unwrap();
    static ref VALUE_SET_DISEASE: ValueSet = serde_json::from_str(VALUE_SET_DISEASE_STR).unwrap();
    static ref VALUE_SET_TEST_MANUFACTURER: ValueSet = serde_json::from_str(VALUE_SET_TEST_MANUFACTURER_STR).unwrap();
    static ref VALUE_SET_TEST_RESULT: ValueSet = serde_json::from_str(VALUE_SET_TEST_RESULT_STR).unwrap();
    static ref VALUE_SET_TEST_TYPE: ValueSet = serde_json::from_str(VALUE_SET_TEST_TYPE_STR).unwrap();
    static ref VALUE_SET_VACCINE_MANUFACTURER: ValueSet = serde_json::from_str(VALUE_SET_VACCINE_MANUFACTURER_STR).unwrap();
    static ref VALUE_SET_VACCINE_PRODUCT: ValueSet = serde_json::from_str(VALUE_SET_VACCINE_PRODUCT_STR).unwrap();
    static ref VALUE_SET_VACCINE_PROPHYLAXIS: ValueSet = serde_json::from_str(VALUE_SET_VACCINE_PROPHYLAXIS_STR).unwrap();

    static ref TR_HES_REGEX: regex::Regex = regex::Regex::new(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}\|[\w\d]{4}-?[\w\d]{4}-?[\w\d]{2}$").unwrap();
}

#[derive(Debug, Deserialize)]
struct UKSigningCert {
    #[serde(deserialize_with = "de_base64")]
    kid: Vec<u8>,
    #[serde(rename = "publicKey", deserialize_with = "de_base64_ec_key")]
    public_key: openssl::ec::EcKey<openssl::pkey::Public>,
}

fn de_base64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d).and_then(|s|
        base64::decode(&s).map_err(serde::de::Error::custom)
    )
}

fn de_base64_ec_key<'de, D: serde::Deserializer<'de>>(d: D) -> Result<openssl::ec::EcKey<openssl::pkey::Public>, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d)
        .and_then(|s| base64::decode(&s).map_err(serde::de::Error::custom))
        .and_then(|c| openssl::ec::EcKey::public_key_from_der(&c).map_err(serde::de::Error::custom))
}

#[derive(Debug)]
struct PassSigningCerts(std::collections::HashMap<PassSigningCertKey, PassSigningCert>);

#[derive(Debug, Hash, Eq, PartialEq)]
struct PassSigningCertKey {
    kid: Vec<u8>,
    iss: String,
}

#[derive(Debug)]
struct PassSigningCert {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[derive(Debug, Serialize)]
struct PKPass {
    description: String,
    #[serde(rename = "formatVersion")]
    format_version: u32,
    #[serde(rename = "organizationName")]
    org_name: String,
    #[serde(rename = "passTypeIdentifier")]
    type_id: String,
    #[serde(rename = "serialNumber")]
    serial: String,
    #[serde(rename = "teamIdentifier")]
    team_id: String,
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    exp_date: Option<DateTime<Utc>>,
    #[serde(default)]
    voided: bool,
    #[serde(flatten)]
    pass_style: PKPassStyle,
    #[serde(rename = "backgroundColor", skip_serializing_if = "Option::is_none")]
    bg_colour: Option<String>,
    #[serde(rename = "foregroundColor", skip_serializing_if = "Option::is_none")]
    fg_colour: Option<String>,
    #[serde(rename = "labelColor", skip_serializing_if = "Option::is_none")]
    label_colour: Option<String>,
    #[serde(rename = "logoText", skip_serializing_if = "Option::is_none")]
    logo_text: Option<String>,
    #[serde(rename = "webServiceURL", skip_serializing_if = "Option::is_none")]
    web_service_url: Option<String>,
    #[serde(rename = "authenticationToken", skip_serializing_if = "Option::is_none")]
    authentication_token: Option<String>,
    #[serde(rename = "sharingProhibited", skip_serializing_if = "Option::is_none")]
    sharing_prohibited: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    barcode: Option<PKPassBarcode>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    barcodes: Vec<PKPassBarcode>,
}

#[derive(Debug, Serialize)]
#[allow(unused)]
enum PKPassStyle {
    #[serde(rename = "boardingPass")]
    BoardingPass(PKPassStructure),
    #[serde(rename = "coupon")]
    Coupon(PKPassStructure),
    #[serde(rename = "eventTicket")]
    EventTicket(PKPassStructure),
    #[serde(rename = "generic")]
    Generic(PKPassStructure),
    #[serde(rename = "storeCard")]
    StoreCard(PKPassStructure),
}

#[derive(Debug, Serialize)]
struct PKPassStructure {
    #[serde(rename = "auxiliaryFields", skip_serializing_if = "Vec::is_empty")]
    aux_fields: Vec<PKPassField>,
    #[serde(rename = "backFields", skip_serializing_if = "Vec::is_empty")]
    back_fields: Vec<PKPassField>,
    #[serde(rename = "headerFields", skip_serializing_if = "Vec::is_empty")]
    header_fields: Vec<PKPassField>,
    #[serde(rename = "primaryFields", skip_serializing_if = "Vec::is_empty")]
    primary_fields: Vec<PKPassField>,
    #[serde(rename = "secondaryFields", skip_serializing_if = "Vec::is_empty")]
    secondary_fields: Vec<PKPassField>,
}

#[derive(Debug, Serialize, Default)]
struct PKPassField {
    #[serde(rename = "attributedValue", skip_serializing_if = "Option::is_none")]
    attributed_value: Option<String>,
    #[serde(rename = "changeMessage", skip_serializing_if = "Option::is_none")]
    change_message: Option<String>,
    #[serde(rename = "dataDetectorTypes", skip_serializing_if = "Option::is_none")]
    data_detectors: Option<Vec<PKDataDetector>>,
    #[serde(rename = "textAlignment", skip_serializing_if = "Option::is_none")]
    text_alignment: Option<PKTextAlignment>,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    value: String,
    #[serde(rename = "dateStyle", skip_serializing_if = "Option::is_none")]
    date_style: Option<PKDateStyle>,
    #[serde(rename = "timeStyle", skip_serializing_if = "Option::is_none")]
    time_style: Option<PKDateStyle>,
    #[serde(rename = "numberStyle", skip_serializing_if = "Option::is_none")]
    number_style: Option<PKNumberStyle>,
    #[serde(rename = "ignoresTimeZone", skip_serializing_if = "Option::is_none")]
    ignores_time_zone: Option<bool>,
    #[serde(rename = "isRelative", skip_serializing_if = "Option::is_none")]
    is_relative: Option<bool>,
    #[serde(rename = "currencyCode", skip_serializing_if = "Option::is_none")]
    currency_code: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[allow(unused)]
enum PKBarcodeFormat {
    #[serde(rename = "PKBarcodeFormatQR")]
    QR,
    #[serde(rename = "PKBarcodeFormatPDF417")]
    PDF417,
    #[serde(rename = "PKBarcodeFormatAztec")]
    Aztec,
    #[serde(rename = "PKBarcodeFormatCode128")]
    Code128,
}

#[derive(Debug, Serialize, Clone)]
#[allow(unused)]
enum PKDataDetector {
    #[serde(rename = "PKDataDetectorTypePhoneNumber")]
    PhoneNumber,
    #[serde(rename = "PKDataDetectorTypeLink")]
    Link,
    #[serde(rename = "PKDataDetectorTypeAddress")]
    Address,
    #[serde(rename = "PKDataDetectorTypeCalendarEvent")]
    CalendarEvent,
}

#[derive(Debug, Serialize, Clone)]
#[allow(unused)]
enum PKTextAlignment {
    #[serde(rename = "PKTextAlignmentLeft")]
    Left,
    #[serde(rename = "PKTextAlignmentCenter")]
    Center,
    #[serde(rename = "PKTextAlignmentRight")]
    Right,
    #[serde(rename = "PKTextAlignmentNatural")]
    Natural,
}

#[derive(Debug, Serialize, Clone)]
#[allow(unused)]
enum PKDateStyle {
    #[serde(rename = "PKDateStyleNone")]
    None,
    #[serde(rename = "PKDateStyleShort")]
    Short,
    #[serde(rename = "PKDateStyleMedium")]
    Medium,
    #[serde(rename = "PKDateStyleLong")]
    Long,
    #[serde(rename = "PKDateStyleFull")]
    Full,
}

#[derive(Debug, Serialize, Clone)]
#[allow(unused)]
enum PKNumberStyle {
    #[serde(rename = "PKNumberStyleDecimal")]
    Decimal,
    #[serde(rename = "PKNumberStylePercent")]
    Percent,
    #[serde(rename = "PKNumberStyleScientific")]
    Scientific,
    #[serde(rename = "PKNumberStyleSpellOut")]
    SpellOut,
}

#[derive(Debug, Serialize, Clone)]
struct PKPassBarcode {
    #[serde(rename = "altText", skip_serializing_if = "Option::is_none")]
    alt_text: Option<String>,
    format: PKBarcodeFormat,
    message: String,
    #[serde(rename = "messageEncoding")]
    message_encoding: String,
}

fn strip_uvci(uvci: &str) -> &str {
    let bare_uvci_with_checksum = uvci.strip_prefix("URN:UVCI:").unwrap_or(uvci);
    bare_uvci_with_checksum.rsplit_once("#").map(|(a, _b)| a).unwrap_or(bare_uvci_with_checksum)
}

fn ehealth_payload_to_pkpass(payload: EHealthPayload, msg: String) -> Result<PKPass, &'static str> {
    let serial = match &payload.hcert.eu_dgc_v1.group {
        EUDigitalGreenCertGroup::Vaccination(v) => match v.first() {
            Some(d) => format!("V:{}:{}:{}", strip_uvci(&d.id), d.dose, d.series),
            None => return Err("invalid payload")
        },
        EUDigitalGreenCertGroup::Test(t) => match t.first() {
            Some(d) => format!("T:{}", strip_uvci(&d.id)),
            None => return Err("invalid payload")
        }
        EUDigitalGreenCertGroup::Recovery(r) => match r.first() {
            Some(d) => format!("R:{}", strip_uvci(&d.id)),
            None => return Err("invalid payload")
        }
    };

    let disease = match &payload.hcert.eu_dgc_v1.group {
        EUDigitalGreenCertGroup::Vaccination(v) => match v.first() {
            Some(d) => d.targeted.display.clone(),
            None => unreachable!()
        },
        EUDigitalGreenCertGroup::Test(t) => match t.first() {
            Some(d) => d.targeted.display.clone(),
            None => unreachable!()
        }
        EUDigitalGreenCertGroup::Recovery(r) => match r.first() {
            Some(d) => d.targeted.display.clone(),
            None => unreachable!()
        }
    };

    let issued_by = match &payload.hcert.eu_dgc_v1.group {
        EUDigitalGreenCertGroup::Vaccination(v) => match v.first() {
            Some(d) => d.issuer.clone(),
            None => unreachable!()
        },
        EUDigitalGreenCertGroup::Test(t) => match t.first() {
            Some(d) => d.issuer.clone(),
            None => unreachable!()
        }
        EUDigitalGreenCertGroup::Recovery(r) => match r.first() {
            Some(d) => d.issuer.clone(),
            None => unreachable!()
        }
    };

    let barcode = PKPassBarcode {
        alt_text: None,
        format: PKBarcodeFormat::QR,
        message: msg,
        message_encoding: "iso-8859-1".to_string(),
    };

    let mut aux_fields = vec![];
    let mut back_fields = vec![PKPassField {
        data_detectors: Some(vec![]),
        key: "exp".to_string(),
        label: Some("Valid until".to_string()),
        value: payload.exp.to_rfc3339(),
        date_style: Some(PKDateStyle::Long),
        time_style: Some(PKDateStyle::Long),
        ..Default::default()
    }, PKPassField {
        data_detectors: Some(vec![]),
        key: "iss".to_string(),
        label: Some("Issued by".to_string()),
        value: issued_by.clone(),
        ..Default::default()
    }];
    let mut secondary_fields = vec![PKPassField {
        data_detectors: Some(vec![]),
        key: "dob".to_string(),
        label: Some("Date of Birth".to_string()),
        value: Utc.from_utc_date(&payload.hcert.eu_dgc_v1.dob).and_hms(0, 0, 0).to_rfc3339(),
        date_style: Some(PKDateStyle::Long),
        time_style: Some(PKDateStyle::None),
        ignores_time_zone: Some(true),
        ..Default::default()
    }];

    match &payload.hcert.eu_dgc_v1.group {
        EUDigitalGreenCertGroup::Vaccination(v) => match v.first() {
            Some(d) => {
                aux_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "vc".to_string(),
                    label: Some("Vaccine".to_string()),
                    value: d.vaccine.display.clone(),
                    ..Default::default()
                });
                secondary_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "dose".to_string(),
                    label: Some("Dose".to_string()),
                    value: format!("{} of {}", d.dose, d.series),
                    ..Default::default()
                });
                aux_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "dt".to_string(),
                    label: Some("Date of Vaccination".to_string()),
                    value: Utc.from_utc_date(&d.date).and_hms(0, 0, 0).to_rfc3339(),
                    date_style: Some(PKDateStyle::Long),
                    time_style: Some(PKDateStyle::None),
                    ignores_time_zone: Some(true),
                    ..Default::default()
                });
                back_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "mn".to_string(),
                    label: Some("Manufacturer".to_string()),
                    value: d.manufacturer.display.clone(),
                    ..Default::default()
                });
                back_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "pd".to_string(),
                    label: Some("Product".to_string()),
                    value: d.product.display.clone(),
                    ..Default::default()
                });
                back_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "co".to_string(),
                    label: Some("Country".to_string()),
                    value: d.country.display.clone(),
                    ..Default::default()
                });
            }
            None => unreachable!()
        },
        EUDigitalGreenCertGroup::Test(t) => match t.first() {
            Some(d) => {
                secondary_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "tr".to_string(),
                    label: Some("Result".to_string()),
                    value: d.result.display.clone(),
                    ..Default::default()
                });
                aux_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "dt".to_string(),
                    label: Some("Date of test".to_string()),
                    value: Utc.from_utc_date(&d.sample_date).and_hms(0, 0, 0).to_rfc3339(),
                    date_style: Some(PKDateStyle::Long),
                    time_style: Some(PKDateStyle::None),
                    ignores_time_zone: Some(true),
                    ..Default::default()
                });
                back_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "tt".to_string(),
                    label: Some("Test type".to_string()),
                    value: d.test_type.display.clone(),
                    ..Default::default()
                });
                if let Some(nm) = &d.name {
                    back_fields.push(PKPassField {
                        data_detectors: Some(vec![]),
                        key: "nm".to_string(),
                        label: Some("Test name".to_string()),
                        value: nm.clone(),
                        ..Default::default()
                    });
                }
                if let Some(tc) = &d.centre {
                    back_fields.push(PKPassField {
                        data_detectors: Some(vec![]),
                        key: "tc".to_string(),
                        label: Some("Test centre".to_string()),
                        value: tc.clone(),
                        ..Default::default()
                    });
                }
                back_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "co".to_string(),
                    label: Some("Country".to_string()),
                    value: d.country.display.clone(),
                    ..Default::default()
                });
            }
            None => unreachable!()
        }
        EUDigitalGreenCertGroup::Recovery(r) => match r.first() {
            Some(d) => {
                aux_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "df".to_string(),
                    label: Some("Valid from".to_string()),
                    value: Utc.from_utc_date(&d.valid_from_date).and_hms(0, 0, 0).to_rfc3339(),
                    date_style: Some(PKDateStyle::Long),
                    time_style: Some(PKDateStyle::None),
                    ignores_time_zone: Some(true),
                    ..Default::default()
                });
                aux_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "du".to_string(),
                    label: Some("Valid until".to_string()),
                    value: Utc.from_utc_date(&d.valid_until_date).and_hms(0, 0, 0).to_rfc3339(),
                    date_style: Some(PKDateStyle::Long),
                    time_style: Some(PKDateStyle::None),
                    ignores_time_zone: Some(true),
                    ..Default::default()
                });
                back_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "fr".to_string(),
                    label: Some("Date of first positive test".to_string()),
                    date_style: Some(PKDateStyle::Long),
                    time_style: Some(PKDateStyle::None),
                    ignores_time_zone: Some(true),
                    value: Utc.from_utc_date(&d.first_positive_test_date).and_hms(0, 0, 0).to_rfc3339(),
                    ..Default::default()
                });
                back_fields.push(PKPassField {
                    data_detectors: Some(vec![]),
                    key: "co".to_string(),
                    label: Some("Country".to_string()),
                    value: d.country.display.clone(),
                    ..Default::default()
                });
            }
            None => unreachable!()
        }
    }


    Ok(PKPass {
        format_version: 1,
        description: if matches!(payload.hcert.eu_dgc_v1.group, EUDigitalGreenCertGroup::Vaccination(_)) {
            "eHealth digital vaccination certificate".to_string()
        } else if matches!(payload.hcert.eu_dgc_v1.group, EUDigitalGreenCertGroup::Test(_)) {
            "eHealth digital test certificate".to_string()
        } else if matches!(payload.hcert.eu_dgc_v1.group, EUDigitalGreenCertGroup::Recovery(_)) {
            "eHealth digital recovery certificate".to_string()
        } else {
            "eHealth digital certificate".to_string()
        },
        org_name: issued_by,
        type_id: PASS_TYPE_ID.to_string(),
        serial,
        team_id: PASS_TEAM_ID.to_string(),
        voided: false,
        sharing_prohibited: Some(true),
        pass_style: PKPassStyle::Generic(PKPassStructure {
            aux_fields,
            back_fields,
            header_fields: vec![PKPassField {
                data_detectors: Some(vec![]),
                key: "tg".to_string(),
                label: Some("For".to_string()),
                value: disease,
                ..Default::default()
            }],
            primary_fields: vec![PKPassField {
                data_detectors: Some(vec![]),
                key: "fn".to_string(),
                label: Some("Name".to_string()),
                value: format!("{} {}", payload.hcert.eu_dgc_v1.name.forename, payload.hcert.eu_dgc_v1.name.surname),
                ..Default::default()
            }],
            secondary_fields,
        }),
        bg_colour: Some("rgb(0, 51, 153)".to_string()),
        fg_colour: Some("rgb(255, 255, 255)".to_string()),
        label_colour: Some("rgb(255, 204, 0)".to_string()),
        logo_text: Some(if matches!(payload.hcert.eu_dgc_v1.group, EUDigitalGreenCertGroup::Vaccination(_)) {
            "Vaccination".to_string()
        } else if matches!(payload.hcert.eu_dgc_v1.group, EUDigitalGreenCertGroup::Test(_)) {
            "Test".to_string()
        } else if matches!(payload.hcert.eu_dgc_v1.group, EUDigitalGreenCertGroup::Recovery(_)) {
            "Recovery".to_string()
        } else {
            "Certificate".to_string()
        }),
        web_service_url: None,
        authentication_token: None,
        exp_date: Some(payload.exp),
        barcode: Some(barcode.clone()),
        barcodes: vec![barcode],
    })
}

fn turkey_payload_to_pkpass(msg: String) -> Result<PKPass, &'static str> {
    let serial = match msg.strip_prefix("https://covidasidogrulama.saglik.gov.tr/api/CovidAsiKartiDogrula?Guid=") {
        Some(s) => s,
        None => return Err("invalid payload")
    };

    let barcode = PKPassBarcode {
        alt_text: None,
        format: PKBarcodeFormat::QR,
        message: msg.clone(),
        message_encoding: "iso-8859-1".to_string(),
    };

    Ok(PKPass {
        format_version: 1,
        description: "Turkey vaccination certificate".to_string(),
        org_name: "Government of Turkey".to_string(),
        type_id: PASS_TYPE_ID.to_string(),
        serial: serial.to_string(),
        team_id: PASS_TEAM_ID.to_string(),
        voided: false,
        sharing_prohibited: Some(true),
        pass_style: PKPassStyle::Generic(PKPassStructure {
            aux_fields: vec![],
            back_fields: vec![PKPassField {
                data_detectors: Some(vec![
                    PKDataDetector::Link
                ]),
                key: "vc".to_string(),
                label: Some("View certificate".to_string()),
                value: msg,
                ..Default::default()
            }],
            header_fields: vec![PKPassField {
                data_detectors: Some(vec![]),
                key: "tg".to_string(),
                label: Some("For".to_string()),
                value: "COVID-19".to_string(),
                ..Default::default()
            }],
            primary_fields: vec![PKPassField {
                data_detectors: Some(vec![]),
                key: "iss".to_string(),
                label: Some("Issued by".to_string()),
                value: "Government of Turkey".to_string(),
                ..Default::default()
            }],
            secondary_fields: vec![],
        }),
        bg_colour: Some("rgb(185, 232, 234)".to_string()),
        fg_colour: Some("rgb(0, 0, 0)".to_string()),
        label_colour: Some("rgb(27, 182, 193)".to_string()),
        logo_text: Some("Vaccination".to_string()),
        web_service_url: None,
        authentication_token: None,
        exp_date: None,
        barcode: Some(barcode.clone()),
        barcodes: vec![barcode],
    })
}

fn turkey_hes_payload_to_pkpass(msg: String) -> Result<PKPass, &'static str> {
    let hes_code = match msg.split_once("|") {
        Some(s) => s.1,
        None => return Err("invalid payload")
    };

    let barcode = PKPassBarcode {
        alt_text: None,
        format: PKBarcodeFormat::QR,
        message: msg.clone(),
        message_encoding: "iso-8859-1".to_string(),
    };

    Ok(PKPass {
        format_version: 1,
        description: "Turkey HES certificate".to_string(),
        org_name: "Government of Turkey".to_string(),
        type_id: PASS_TYPE_ID.to_string(),
        serial: hes_code.to_string(),
        team_id: PASS_TEAM_ID.to_string(),
        voided: false,
        sharing_prohibited: Some(true),
        pass_style: PKPassStyle::Generic(PKPassStructure {
            aux_fields: vec![],
            back_fields: vec![],
            header_fields: vec![],
            primary_fields: vec![PKPassField {
                data_detectors: Some(vec![]),
                key: "hes".to_string(),
                label: Some("Code".to_string()),
                value: format!("{}-{}-{}", &hes_code[0..4], &hes_code[4..8], &hes_code[8..]),
                ..Default::default()
            }],
            secondary_fields: vec![PKPassField {
                data_detectors: Some(vec![]),
                key: "iss".to_string(),
                label: Some("Issued by".to_string()),
                value: "Government of Turkey".to_string(),
                ..Default::default()
            }],
        }),
        bg_colour: Some("rgb(90, 168, 0)".to_string()),
        fg_colour: Some("rgb(255, 255, 255)".to_string()),
        label_colour: Some("rgb(255, 87, 34)".to_string()),
        logo_text: Some("HES Code".to_string()),
        web_service_url: None,
        authentication_token: None,
        exp_date: None,
        barcode: Some(barcode.clone()),
        barcodes: vec![barcode],
    })
}

struct PKPassSigningKeys {
    public_cert: openssl::x509::X509,
    private_key: openssl::pkey::PKey<openssl::pkey::Private>,
    intermediate_certs: openssl::stack::Stack<openssl::x509::X509>,
}

fn sign_pkpass(pass: &PKPass, signing_keys: &PKPassSigningKeys) -> Result<Vec<u8>, String> {
    let pass_bytes = serde_json::to_vec(pass).map_err(|e| format!("Unable to serialize pass: {}", e))?;

    let mut manifest = std::collections::HashMap::<String, String>::new();

    let mut buf = vec![];
    let mut archive = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));

    archive.start_file("pass.json", zip::write::FileOptions::default())
        .map_err(|e| format!("Failed to write ZIP file: {}", e))?;
    archive.write(&pass_bytes)
        .map_err(|e| format!("Failed to write ZIP file: {}", e))?;

    let pass_hash = hex::encode(
        openssl::hash::hash(openssl::hash::MessageDigest::sha1(), &pass_bytes)
            .map_err(|e| format!("Failed to calculate manifest: {}", e))?
    );
    manifest.insert("pass.json".to_string(), pass_hash);

    for file in PASS_ASSETS.files() {
        let file_path = file.path().to_string_lossy();
        let file_contents = file.contents();
        archive.start_file(file_path.to_string(), zip::write::FileOptions::default())
            .map_err(|e| format!("Failed to write ZIP file: {}", e))?;
        archive.write(file_contents)
            .map_err(|e| format!("Failed to write ZIP file: {}", e))?;

        let file_hash = hex::encode(
            openssl::hash::hash(openssl::hash::MessageDigest::sha1(), file_contents)
                .map_err(|e| format!("Failed to calculate manifest: {}", e))?
        );
        manifest.insert(file_path.to_string(), file_hash);
    }

    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|e| format!("Unable to serialize manifest: {}", e))?;

    archive.start_file("manifest.json", zip::write::FileOptions::default())
        .map_err(|e| format!("Failed to write ZIP file: {}", e))?;
    archive.write(&manifest_bytes)
        .map_err(|e| format!("Failed to write ZIP file: {}", e))?;

    let pkcs7 = openssl::pkcs7::Pkcs7::sign(
        signing_keys.public_cert.as_ref(),
        signing_keys.private_key.as_ref(),
        signing_keys.intermediate_certs.as_ref(),
        &manifest_bytes,
        openssl::pkcs7::Pkcs7Flags::DETACHED | openssl::pkcs7::Pkcs7Flags::NOCRL,
    ).map_err(|e| format!("Unable to sign manifest: {}", e))?;
    let pkcs7_bytes = pkcs7.to_der().map_err(|e| format!("Unable to serialize signature: {}", e))?;

    archive.start_file("signature", zip::write::FileOptions::default())
        .map_err(|e| format!("Failed to write ZIP file: {}", e))?;
    archive.write(&pkcs7_bytes)
        .map_err(|e| format!("Failed to write ZIP file: {}", e))?;

    archive.finish().map_err(|e| format!("Failed to write ZIP file: {}", e))?;
    std::mem::drop(archive);

    Ok(buf)
}

struct PKPassResponse(Vec<u8>);

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for PKPassResponse {
    fn respond_to(self, _req: &'r rocket::request::Request<'_>) -> rocket::response::Result<'o> {
        rocket::Response::build()
            .header(rocket::http::ContentType::new("application", "vnd.apple.pkpass"))
            .raw_header("Content-Disposition", "attachment; filename=\"ehealth.pkpass\"")
            .sized_body(self.0.len(), std::io::Cursor::new(self.0))
            .ok()
    }
}

#[derive(Debug, Deserialize)]
struct EUDigitalGreenCertName {
    #[serde(rename = "fn")]
    surname: String,
    #[serde(rename = "fnt")]
    std_surname: String,
    #[serde(rename = "gn")]
    forename: String,
    #[serde(rename = "gnt")]
    std_forname: String,
}

#[derive(Debug, Deserialize)]
struct EUDigitalGreenCertV1 {
    ver: String,
    #[serde(rename = "nam")]
    name: EUDigitalGreenCertName,
    #[serde(deserialize_with = "de_date")]
    dob: NaiveDate,
    #[serde(flatten)]
    group: EUDigitalGreenCertGroup,
}

#[derive(Debug, Deserialize)]
enum EUDigitalGreenCertGroup {
    #[serde(rename = "v")]
    Vaccination(Vec<EUDigitalGreenCertVaccination>),
    #[serde(rename = "t")]
    Test(Vec<EUDigitalGreenCertTest>),
    #[serde(rename = "r")]
    Recovery(Vec<EUDigitalGreenCertRecovery>),
}

fn de_value_set_disease<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ValueSetValue, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d).and_then(|s|
        VALUE_SET_DISEASE.values.get(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("Unknown disease: {}", s)))
            .map(|v| v.clone())
    )
}

fn de_value_set_vaccine<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ValueSetValue, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d).and_then(|s|
        VALUE_SET_VACCINE_PROPHYLAXIS.values.get(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("Unknown vaccine: {}", s)))
            .map(|v| v.clone())
    )
}

fn de_value_set_vaccine_product<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ValueSetValue, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d).and_then(|s|
        VALUE_SET_VACCINE_PRODUCT.values.get(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("Unknown vaccine product: {}", s)))
            .map(|v| v.clone())
    )
}

fn de_value_set_vaccine_manufacturer<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ValueSetValue, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d).and_then(|s|
        VALUE_SET_VACCINE_MANUFACTURER.values.get(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("Unknown vaccine manufacturer: {}", s)))
            .map(|v| v.clone())
    )
}

fn de_value_set_test_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ValueSetValue, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d).and_then(|s|
        VALUE_SET_TEST_TYPE.values.get(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("Unknown test type: {}", s)))
            .map(|v| v.clone())
    )
}

fn de_value_set_test_result<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ValueSetValue, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d).and_then(|s|
        VALUE_SET_TEST_RESULT.values.get(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("Unknown test result: {}", s)))
            .map(|v| v.clone())
    )
}

fn de_value_set_country<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ValueSetValue, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d).and_then(|s|
        VALUE_SET_COUNTRY_CODE.values.get(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("Unknown country: {}", s)))
            .map(|v| v.clone())
    )
}

fn de_date<'de, D: serde::Deserializer<'de>>(d: D) -> Result<NaiveDate, D::Error> {
    use serde::de::Deserialize;
    String::deserialize(d).and_then(|s|
        NaiveDate::parse_from_str(&s, "%Y-%m-%d")
            .map_err(serde::de::Error::custom)
    )
}

#[derive(Debug, Deserialize)]
struct EUDigitalGreenCertVaccination {
    #[serde(rename = "tg", deserialize_with = "de_value_set_disease")]
    targeted: ValueSetValue,
    #[serde(rename = "vp", deserialize_with = "de_value_set_vaccine")]
    vaccine: ValueSetValue,
    #[serde(rename = "mp", deserialize_with = "de_value_set_vaccine_product")]
    product: ValueSetValue,
    #[serde(rename = "ma", deserialize_with = "de_value_set_vaccine_manufacturer")]
    manufacturer: ValueSetValue,
    #[serde(rename = "dn")]
    dose: usize,
    #[serde(rename = "sd")]
    series: usize,
    #[serde(rename = "dt", deserialize_with = "de_date")]
    date: NaiveDate,
    #[serde(rename = "co", deserialize_with = "de_value_set_country")]
    country: ValueSetValue,
    #[serde(rename = "is")]
    issuer: String,
    #[serde(rename = "ci")]
    id: String,
}

#[derive(Debug, Deserialize)]
struct EUDigitalGreenCertTest {
    #[serde(rename = "tg", deserialize_with = "de_value_set_disease")]
    targeted: ValueSetValue,
    #[serde(rename = "tt", deserialize_with = "de_value_set_test_type")]
    test_type: ValueSetValue,
    #[serde(rename = "nm", default)]
    name: Option<String>,
    #[serde(rename = "ma", default)]
    device: Option<String>,
    #[serde(rename = "sc", deserialize_with = "de_date")]
    sample_date: NaiveDate,
    #[serde(rename = "tr", deserialize_with = "de_value_set_test_result")]
    result: ValueSetValue,
    #[serde(rename = "tc", default)]
    centre: Option<String>,
    #[serde(rename = "co", deserialize_with = "de_value_set_country")]
    country: ValueSetValue,
    #[serde(rename = "is")]
    issuer: String,
    #[serde(rename = "ci")]
    id: String,
}

#[derive(Debug, Deserialize)]
struct EUDigitalGreenCertRecovery {
    #[serde(rename = "tg", deserialize_with = "de_value_set_disease")]
    targeted: ValueSetValue,
    #[serde(rename = "fr", deserialize_with = "de_date")]
    first_positive_test_date: NaiveDate,
    #[serde(rename = "df", deserialize_with = "de_date")]
    valid_from_date: NaiveDate,
    #[serde(rename = "du", deserialize_with = "de_date")]
    valid_until_date: NaiveDate,
    #[serde(rename = "co", deserialize_with = "de_value_set_country")]
    country: ValueSetValue,
    #[serde(rename = "is")]
    issuer: String,
    #[serde(rename = "ci")]
    id: String,
}

#[derive(Debug)]
struct EHealthHcert {
    eu_dgc_v1: EUDigitalGreenCertV1,
}

impl<'de> serde::Deserialize<'de> for EHealthHcert {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = EHealthHcert;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("struct EHealthHcert")
            }

            fn visit_map<V: serde::de::MapAccess<'de>>(self, mut map: V) -> Result<Self::Value, V::Error> {
                let mut eu_dgc_v1 = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if eu_dgc_v1.is_some() {
                                return Err(serde::de::Error::duplicate_field("eu_dgc_v1"));
                            }
                            eu_dgc_v1 = Some(map.next_value()?);
                        }
                        f => {
                            return Err(serde::de::Error::unknown_field(&f.to_string(), &["1"]));
                        }
                    }
                }

                let eu_dgc_v1 = eu_dgc_v1.ok_or_else(|| serde::de::Error::missing_field("eu_dgc_v1"))?;

                Ok(EHealthHcert {
                    eu_dgc_v1
                })
            }
        }

        deserializer.deserialize_struct("", &[], Visitor)
    }
}

#[derive(Debug)]
struct EHealthPayload {
    iss: String,
    iat: DateTime<Utc>,
    exp: DateTime<Utc>,
    hcert: EHealthHcert,
}

impl<'de> serde::Deserialize<'de> for EHealthPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = EHealthPayload;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("struct EHealthPayload")
            }

            fn visit_map<V: serde::de::MapAccess<'de>>(self, mut map: V) -> Result<Self::Value, V::Error> {
                let mut iss = None;
                let mut iat = None;
                let mut exp = None;
                let mut hcert = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if iss.is_some() {
                                return Err(serde::de::Error::duplicate_field("iss"));
                            }
                            iss = Some(map.next_value()?);
                        }
                        6 => {
                            if iat.is_some() {
                                return Err(serde::de::Error::duplicate_field("iat"));
                            }
                            let iat_ts = map.next_value::<i64>()?;
                            iat = Some(chrono::Utc.timestamp(iat_ts, 0));
                        }
                        4 => {
                            if exp.is_some() {
                                return Err(serde::de::Error::duplicate_field("exp"));
                            }
                            let exp_ts = map.next_value::<i64>()?;
                            exp = Some(chrono::Utc.timestamp(exp_ts, 0));
                        }
                        -260 => {
                            if hcert.is_some() {
                                return Err(serde::de::Error::duplicate_field("hcert"));
                            }
                            hcert = Some(map.next_value()?);
                        }
                        f => {
                            return Err(serde::de::Error::unknown_field(&f.to_string(), &["1", "6", "4", "-260"]));
                        }
                    }
                }

                let iss = iss.ok_or_else(|| serde::de::Error::missing_field("iss"))?;
                let iat = iat.ok_or_else(|| serde::de::Error::missing_field("iat"))?;
                let exp = exp.ok_or_else(|| serde::de::Error::missing_field("exp"))?;
                let hcert = hcert.ok_or_else(|| serde::de::Error::missing_field("hcert"))?;

                Ok(EHealthPayload {
                    iss,
                    iat,
                    exp,
                    hcert,
                })
            }
        }

        deserializer.deserialize_struct("", &[], Visitor)
    }
}

#[get("/")]
fn index() -> rocket_dyn_templates::Template {
    rocket_dyn_templates::Template::render("index", std::collections::HashMap::<(), ()>::new())
}

#[get("/privacy")]
fn privacy() -> rocket_dyn_templates::Template {
    rocket_dyn_templates::Template::render("privacy", std::collections::HashMap::<(), ()>::new())
}

#[derive(Debug, Serialize)]
struct ErrorInfo {
    error: &'static str,
}

#[get("/qr-data?<d>")]
fn qr_data(
    d: String,
    signing_certs: &rocket::State<PassSigningCerts>,
    pass_signing_keys: &rocket::State<PKPassSigningKeys>,
) -> Result<PKPassResponse, rocket_dyn_templates::Template> {
    let pkpass = if d.starts_with("HC1:") {
        let hc_data_deflated = match base45::decode(&d[4..]) {
            Ok(d) => d,
            Err(e) => {
                println!("Can't decode Base45: {}", e);
                return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                    error: "Invalid Base45"
                }));
            }
        };
        let hc_data = match inflate::inflate_bytes(&hc_data_deflated) {
            Ok(d) => d,
            Err(e) => {
                println!("Can't decode DEFLATE: {}", e);
                return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                    error: "Invalid DEFLATE encoding"
                }));
            }
        };

        let cose_data = match coset::CoseSign1::from_tagged_slice(&hc_data) {
            Ok(d) => d,
            Err(e) => {
                println!("Can't decode COSE: {}", e);
                return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                    error: "Invalid COSE data"
                }));
            }
        };

        let payload_bytes = match &cose_data.payload {
            Some(d) => d,
            None => {
                println!("No COSE payload");
                return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                    error: "No payload in COSE data"
                }));
            }
        };

        let payload = match serde_cbor::from_slice::<EHealthPayload>(&payload_bytes) {
            Ok(d) => d,
            Err(e) => {
                println!("Can't decode payload: {}", e);
                return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                    error: "Invalid payload"
                }));
            }
        };

        if VERIFIABLE_COUNTRIES.contains(&payload.iss.as_str()) {
            let cert_key = PassSigningCertKey {
                iss: payload.iss.clone(),
                kid: cose_data.protected.key_id.clone(),
            };

            let signing_cert = match signing_certs.0.get(&cert_key) {
                Some(d) => d,
                None => {
                    println!("No known signing key");
                    return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                        error: "Signed by an unknown key"
                    }));
                }
            };

            match cose_data.verify_signature(&[], |sig, data| {
                match cose_data.protected.alg.clone().unwrap_or_default() {
                    coset::Algorithm::Assigned(coset::iana::Algorithm::ES256) => {
                        if sig.len() != 64 {
                            return Err("invalid signature length".to_string());
                        }
                        let r = openssl::bn::BigNum::from_slice(&sig[0..32]).map_err(|e| e.to_string())?;
                        let s = openssl::bn::BigNum::from_slice(&sig[32..64]).map_err(|e| e.to_string())?;
                        let sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s).map_err(|e| e.to_string())?;
                        let hash = openssl::hash::hash(
                            openssl::hash::MessageDigest::sha256(), data,
                        ).map_err(|e| e.to_string())?;
                        if sig.verify(
                            hash.as_ref(),
                            signing_cert.pkey.ec_key().map_err(|e| e.to_string())?.as_ref(),
                        ).map_err(|e| e.to_string())? {
                            Ok(())
                        } else {
                            Err("signature failed to verify".to_string())
                        }
                    }
                    coset::Algorithm::Assigned(coset::iana::Algorithm::PS256) => {
                        let mut verifier = openssl::sign::Verifier::new(
                            openssl::hash::MessageDigest::sha256(), &signing_cert.pkey,
                        ).map_err(|e| e.to_string())?;
                        verifier.update(data).map_err(|e| e.to_string())?;
                        if verifier.verify(sig).map_err(|e| e.to_string())? {
                            Ok(())
                        } else {
                            Err("signature failed to verify".to_string())
                        }
                    }
                    a => {
                        return Err(format!("Unsupported signing alg: {:?}", a));
                    }
                }
            }) {
                Ok(_) => {}
                Err(e) => {
                    println!("Signature verification failed: {}", e);
                    return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                        error: "Invalid signature"
                    }));
                }
            }
        }

        match ehealth_payload_to_pkpass(payload, d) {
            Ok(p) => p,
            Err(e) => {
                println!("Unable to create pkpass: {}", e);
                return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                    error: "Invalid pass"
                }));
            }
        }
    } else if d.starts_with("https://covidasidogrulama.saglik.gov.tr/api/CovidAsiKartiDogrula") {
        match turkey_payload_to_pkpass(d) {
            Ok(p) => p,
            Err(e) => {
                println!("Unable to create pkpass: {}", e);
                return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                    error: "Invalid pass"
                }));
            }
        }
    } else if TR_HES_REGEX.is_match(&d) {
        match turkey_hes_payload_to_pkpass(d) {
            Ok(p) => p,
            Err(e) => {
                println!("Unable to create pkpass: {}", e);
                return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                    error: "Invalid pass"
                }));
            }
        }
    } else {
        return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
            error: "Not an eHealth QR code"
        }));
    };

    let pkpass_bytes = match sign_pkpass(&pkpass, &pass_signing_keys) {
        Ok(d) => d,
        Err(e) => {
            println!("Can't encode pass: {}", e);
            return Err(rocket_dyn_templates::Template::render("error", ErrorInfo {
                error: "Unable to generate pass"
            }));
        }
    };

    Ok(PKPassResponse(pkpass_bytes))
}

#[rocket::launch]
fn rocket() -> _ {
    let uk_certs: Vec<UKSigningCert> = reqwest::blocking::get(UK_CERT_URL)
        .expect("Unable to download UK signing certs")
        .json()
        .expect("Unable to decode UK signing certs");

    let mut signing_certs = PassSigningCerts(std::collections::HashMap::new());

    for cert in uk_certs {
        signing_certs.0.insert(PassSigningCertKey {
            iss: "GB".to_string(),
            kid: cert.kid,
        }, PassSigningCert {
            pkey: openssl::pkey::PKey::from_ec_key(cert.public_key).unwrap()
        });
    }

    let mut intermediate_certs = openssl::stack::Stack::new().unwrap();

    intermediate_certs.push(openssl::x509::X509::from_der(
        &std::fs::read("./priv/AppleWWDRCA.cer").expect("Unable to read intermediate cert")
    ).expect("Invalid intermediate cert")).unwrap();

    let signing_keys = PKPassSigningKeys {
        public_cert: openssl::x509::X509::from_der(
            &std::fs::read("./priv/pass.cer").expect("Unable to read public signing key")
        ).expect("Invalid public signing key"),
        private_key: openssl::pkey::PKey::private_key_from_der(
            &std::fs::read("./priv/pass.key").expect("Unable to read public signing key")
        ).expect("Invalid private signing key"),
        intermediate_certs,
    };

    rocket::build()
        .attach(rocket_dyn_templates::Template::fairing())
        .manage(signing_certs)
        .manage(signing_keys)
        .mount("/static", rocket::fs::FileServer::from("./static"))
        .mount("/", routes![
            index, qr_data, privacy
        ])
}
