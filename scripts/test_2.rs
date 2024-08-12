use bitcoin_script_stack::stack::StackTracker;
use bitcoin_script_stack::interactive::interactive;

pub fn main() {
    let mut stack = StackTracker::new();
    for _ in 0..90 {
        stack.number(1);
    };
    stack.op_sha256();
    stack.debug();
    assert!(stack.run().success);
}

