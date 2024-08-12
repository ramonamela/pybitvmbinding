use bitcoin_script_stack::stack::StackTracker;
use bitcoin_script_stack::interactive::interactive;

pub fn build_witness(stack: &mut StackTracker) {
    stack.hexstr("9fe342e693cf54854e1c6754b8ea4be034ea2ac7");
    stack.number(7);
    stack.hexstr("a3d64e95a648c246e1bc5209290d108b7a964a8a");
    stack.number(5);
    stack.hexstr("02c39d38006a8a8bee9c4f4005b8668185f13443");
    stack.number(8);
    stack.hexstr("8e80ac3fd5905e9d189a5036d8748dd548007601");
    stack.number(6);
    stack.hexstr("177f2825e09f784c6c4aba45148450c1742b5dee");
    stack.number(2);
    stack.hexstr("e3a5e00d8e2952fc0d6a3744839ab5cb9996e83e");
    stack.number(2);
}

pub fn main() {
    let mut stack = StackTracker::new();

    let private_key: &str = "583d982939949f844a0cfd3521c7cba6de9bb9b6d7c00668805674bb30091f51";
    println!("private_key: {}", private_key);
    
    build_witness(&mut stack);

    stack.set_breakpoint("random");

    stack.op_true();

    stack.debug();
    // interactive(&stack);
}

