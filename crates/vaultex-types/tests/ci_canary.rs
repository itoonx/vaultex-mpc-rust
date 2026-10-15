//! CI canary (T00-8, ROADMAP M5 #6): this branch exists only to prove a failing test turns CI red.
//! Never merge it.

#[test]
fn ci_canary_must_fail() {
    panic!("CI canary: this run must be red");
}
