//! Checks on the incident catalogue itself (T13-3): coverage, registry linkage, one fault per case,
//! well-formed framing, public-safe wording, and a replay harness that cannot pass vacuously. The
//! kernel's own replay (T05-9) runs the same catalogue against the real decoder and policy.

use std::collections::HashSet;

use vaultex_redteam::{replay, tron, IncidentClass, Scenario};
use vaultex_types::{Decision, Refusal, RefusalCode, MAX_RAW_TX_BYTES};

#[test]
fn every_incident_class_has_cases() {
    let cases = tron::cases();
    for class in IncidentClass::ALL {
        assert!(
            cases.iter().any(|c| c.class == class),
            "no case for {class:?}"
        );
    }
}

#[test]
fn ids_are_unique() {
    let ids: Vec<String> = tron::controls()
        .iter()
        .map(|c| c.id.to_string())
        .chain(tron::cases().into_iter().map(|c| c.id))
        .collect();
    let unique: HashSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate ids");
}

#[test]
fn expected_codes_are_known_final_refusals() {
    for c in tron::cases() {
        assert!(
            (1..=2).contains(&c.expect.len()),
            "{}: one or two codes",
            c.id
        );
        for code in c.expect {
            assert!(
                code.name().is_some(),
                "{}: {code:?} not in the registry",
                c.id
            );
            assert!(!code.is_retryable(), "{}: {code:?} is not a refusal", c.id);
        }
    }
}

/// One fault per case: no case may equal a control (its mutation got lost) or another case (a
/// duplicate). Both would also make the kernel's replay meaningless for that row.
#[test]
fn every_case_differs_from_the_controls_and_from_each_other() {
    let controls: Vec<Scenario> = tron::controls().into_iter().map(|c| c.scenario).collect();
    let mut seen = HashSet::new();
    for c in tron::cases() {
        assert!(
            !controls.contains(&c.scenario),
            "{} is identical to a control",
            c.id
        );
        assert!(seen.insert(c.scenario), "{} duplicates another case", c.id);
    }
}

/// Every transaction is wire-valid protobuf at every layer (raw, contract, parameter, value) and
/// fits the size cap, so a case is refused for the fault it names, not for broken framing.
#[test]
fn transactions_are_well_framed_and_within_the_size_cap() {
    let all = tron::controls()
        .into_iter()
        .map(|c| (c.id.to_string(), c.scenario))
        .chain(tron::cases().into_iter().map(|c| (c.id, c.scenario)));
    for (id, s) in all {
        assert!(
            s.raw_tx.len() <= MAX_RAW_TX_BYTES,
            "{id}: over the size cap"
        );
        assert!(well_framed(&s.raw_tx), "{id}: broken framing");
    }
}

/// Category-level wording only: no links, code pointers or byte strings in the descriptions.
#[test]
fn summaries_are_category_level() {
    let summaries = tron::controls()
        .iter()
        .map(|c| c.summary)
        .chain(tron::cases().iter().map(|c| c.summary))
        .collect::<Vec<_>>();
    for s in summaries {
        assert!(!s.is_empty() && s.len() <= 120, "length: {s}");
        for banned in ["http", ".rs", "0x", "::"] {
            assert!(!s.contains(banned), "{banned:?} in: {s}");
        }
    }
}

/// The replay harness catches both failure directions, and passes a kernel that answers exactly
/// as the catalogue expects.
#[test]
fn replay_is_not_vacuous() {
    let n_controls = tron::controls().len();
    let n_cases = tron::cases().len();

    // A kernel that accepts everything fails every case and no control.
    assert_eq!(replay(|_| Decision::Accept).len(), n_cases);

    // A kernel that refuses everything as a malformed request fails every row: the controls, and
    // every case, because none is satisfied by a generic envelope refusal.
    let refuse_all = Decision::Refuse(Refusal {
        code: RefusalCode::MALFORMED,
        rule_index: None,
    });
    assert_eq!(replay(|_| refuse_all).len(), n_controls + n_cases);

    // An oracle that answers each scenario with its expected decision passes.
    let mut answers: Vec<(Scenario, Decision)> = tron::controls()
        .into_iter()
        .map(|c| (c.scenario, Decision::Accept))
        .collect();
    answers.extend(tron::cases().into_iter().map(|c| {
        let code = *c.expect.last().unwrap(); // any listed code is acceptable
        let refusal = Refusal {
            code,
            rule_index: None,
        };
        (c.scenario, Decision::Refuse(refusal))
    }));
    let oracle = |s: &Scenario| answers.iter().find(|(a, _)| a == s).unwrap().1;
    assert_eq!(replay(oracle), vec![]);
}

// ── A lax protobuf walker: framing only, no grammar ───────────────────────────────────────────

fn varint(b: &mut &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = b.split_first()?;
        *b = rest;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// A field number and its payload; the payload is `None` for a varint.
type Field<'a> = (u64, Option<&'a [u8]>);

/// The fields of a message, or `None` if the framing is broken.
fn fields(mut b: &[u8]) -> Option<Vec<Field<'_>>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let key = varint(&mut b)?;
        match key & 7 {
            0 => {
                varint(&mut b)?;
                out.push((key >> 3, None));
            }
            2 => {
                let n = usize::try_from(varint(&mut b)?).ok()?;
                if n > b.len() {
                    return None;
                }
                let (payload, rest) = b.split_at(n);
                b = rest;
                out.push((key >> 3, Some(payload)));
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Every message numbered `field` in `msg` is length-delimited and satisfies `inner`.
fn each(msg: &[Field<'_>], field: u64, inner: impl Fn(&[u8]) -> bool) -> bool {
    msg.iter()
        .filter(|(f, _)| *f == field)
        .all(|(_, payload)| payload.is_some_and(&inner))
}

fn well_framed(raw: &[u8]) -> bool {
    let value = |b: &[u8]| fields(b).is_some();
    let any = |b: &[u8]| fields(b).is_some_and(|a| each(&a, 2, value));
    let contract = |b: &[u8]| fields(b).is_some_and(|c| each(&c, 2, any));
    fields(raw).is_some_and(|r| r.iter().any(|(f, _)| *f == 11) && each(&r, 11, contract))
}
