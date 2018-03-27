mod keychain;
mod crypto;
mod item;

#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate getopts;
extern crate rpassword;
extern crate regex;
extern crate clipboard;
extern crate rand;

#[cfg(test)]
mod tests;

use getopts::Options;
use std::env;
use std::io;
use std::io::Write;
use regex::Regex;
use clipboard::{ClipboardProvider,ClipboardContext};
use std::{thread, time};
use std::path::Path;

static mut STDIN_PASSWORD: bool = false;

fn print_usage(exe: &str, opts: Options) {
    let brief = format!("Usage: {0} [options] <operation>

  {0} new
    create new empty database

  {0} passwd
    change password of existing database

  {0} add
    add new entry

  {0} list [<name regexp>]
    list all entries or entries matching given regexp

  {0} copy <name regexp>
    copy password to clipboard, after user presses any key, copy username and exit

  {0} show <name regexp>
    print all fields for matching entries

  Examples:
    $ echo -n bogus12345 | {0} -p ./simple.psafe3 -S list
    Test eight
    Test Four
    Test.Test One
    Test seven
    Test Two
    Test.Test Nine
    Test six
    Test.Test One
    Test Five

    $ echo -n bogus12345 | {0} -p ./simple.psafe3 -S list \\.Test
    Test.Test One
    Test.Test Nine
    Test.Test One

    $ echo -n bogus12345 | {0} -p ./simple.psafe3 -S copy 'Test six'
    Password is now in your clipboard, press ENTER to copy username", exe);

    print!("{}", opts.usage(&brief));
}

fn case_insensitive_re(args: &[String]) -> Regex {
    let re = format!("(?i){}", &args.join(""));
    return Regex::new(&re).expect("Can't parse regular expression");
}

fn op_new(db_path: &str) {
    if Path::new(&db_path).exists() {
        println!("Database '{}' already exists!", &db_path);
        return;
    }

    let password = ask_password("Password: ");
    let password2 = ask_password("Retype password: ");

    if password != password2 {
        println!("Passwords don't match!");
        return;
    }

    let mut kc = keychain::V3::new(&db_path);
    kc.save(&password);
}

fn op_passwd(db_path: &str) {
    let password = ask_password("Current password: ");

    let newpassword = ask_password("New Password: ");
    let newpassword2 = ask_password("Retype new password: ");

    if newpassword != newpassword2 {
        println!("New passwords don't match!");
        return;
    }

    match keychain::V3::open(&db_path, &password) {
        Some(mut kc) => kc.save(&newpassword),
        None => false,
    };
}

fn op_add(db_path: &str) {
    let password = ask_password("Password: ");

    match keychain::V3::open(&db_path, &password) {
        Some(mut kc) => {
            let mut item = item::new();

            let g = ask("Group");
            let t = ask("Title");
            let u = ask("Username");
            let p = ask("Password");
            let n = ask("Notes");

            if g != "" {
                item.insert(item::Kind::Group, &item::Data::Text(g));
            }
            item.insert(item::Kind::Title, &item::Data::Text(t));
            item.insert(item::Kind::Username, &item::Data::Text(u));
            item.insert(item::Kind::Password, &item::Data::Text(p));
            item.insert(item::Kind::Notes, &item::Data::Text(n));
            kc.insert(item);

            kc.save(&password);
        },
        None => (),
    };
}

fn op_list(kc: &keychain::V3, args: &[String]) {
    kc.each_re(&case_insensitive_re(args), &mut |name: &str, _: &item::Item| {
        println!("{}", name);
    });
}

fn op_copy(kc: &keychain::V3, args: &[String]) {
    let mut v = Vec::new();
    kc.each_re(&case_insensitive_re(args), &mut |name: &str, i: &item::Item| {
        let mut user = String::new();
        let mut pass = String::new();

        match i.get(item::Kind::Username) {
            Some(u) => {
                match u {
                    &item::Data::Text(ref v) => user.push_str(v),
                    _ => panic!("Username has wrong type"),
                }
            },
            _ => eprintln!("Username missing, assuming empty string"),
        }

        match i.get(item::Kind::Password) {
            Some(p) => {
                match p {
                    &item::Data::Text(ref v) => pass.push_str(v),
                    _ => panic!("Password has wrong type"),
                }
            },
            _ => eprintln!("Password missing, assuming empty string"),
        }

        v.push((name.to_string(), user, pass));
    });

    let mut selected = 0;

    if v.len() == 0 {
            eprintln!("No entries matching '{}' found", &args.join(""));
            return;
    }

    if v.len() > 1 {
        println!("Select item to copy:");
        for i in 0..v.len() {
            println!("{}) {}", i, v[i].0);
        }

        selected = match read_stdin_number() {
            Some(n) => n,
            None => {
                eprintln!("Can't read selection from stdin");
                return;
            },
        }
    }

    match v.get(selected) {
        Some(s) => clipboard_copy(&s.1, &s.2),
        None => {
            eprintln!("Invalid selection");
            return;
        },
    }
}

fn op_show(kc: &keychain::V3, args: &[String]) {
    kc.each_re(&case_insensitive_re(args), &mut |name: &str, i: &item::Item| {
        println!("{}:", name);
        for (k, v) in i.iter() {
            if *k != item::Kind::UUID {
                println!("\t{:?}: {}", k, v.to_string());
            }
        }
        println!("");
    });
}

fn read_stdin_number() -> Option<usize> {
    let mut t = String::new();
    io::stdin().read_line(&mut t).expect("Can't read line from stdin");

    match t.trim().parse::<usize>() {
        Ok(i) => return Some(i),
        _ => return None,
    };
}

fn wait_for_enter() {
    let mut junk = String::new();
    io::stdin().read_line(&mut junk).expect("Can't wait for newline from stdin");
}

fn ask(question: &str) -> String {
    let mut reply = String::new();
    print!("{}: ", question);
    io::stdout().flush().ok().expect("Can't flush stdout");
    io::stdin().read_line(&mut reply).expect("Can't wait for newline from stdin");
    return reply.trim_right().to_string();
}

fn clipboard_copy(user: &str, pass: &str) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().expect("Can't obtain clipboard context");

    ctx.set_contents(pass.to_owned()).expect("Can't paste password into clipboard");
    println!("Password is now in your clipboard, press ENTER to copy username");
    wait_for_enter();

    ctx.set_contents(user.to_owned()).expect("Can't paste username into clipboard");
    println!("Username is now in your clipboard, you have 15 seconds before the clipboard is flushed");

    thread::sleep(time::Duration::from_secs(15));

    // should be cleared automatically, but try to overwrite anyway
    ctx.set_contents("".to_owned()).expect("Can't clear clipboard");
}

fn run_op(db_path: &str, op: &Vec<String>) -> bool {
    match op[0].as_ref() {
        "new" => op_new(db_path),
        "passwd" => op_passwd(db_path),
        "add" => op_add(db_path),
        "list" => {
            match keychain::V3::open(&db_path, &ask_password("Password: ")) {
                Some(kc) => op_list(&kc, &op[1..]),
                None => {},
            }
        },
        "copy" => {
            match keychain::V3::open(&db_path, &ask_password("Password: ")) {
                Some(kc) => op_copy(&kc, &op[1..]),
                None => {},
            }
        },
        "show" => {
            match keychain::V3::open(&db_path, &ask_password("Password: ")) {
                Some(kc) => op_show(&kc, &op[1..]),
                None => {},
            }
        },
        _ => return false,
    }

    return true;
}

fn ask_password(query: &str) -> String {
    if unsafe { STDIN_PASSWORD } {
        let mut password = String::new();
        io::stdin().read_line(&mut password).expect("Can't read password from stdin");
        return password.trim_right().to_string();
    } else {
        return rpassword::prompt_password_stdout(query).expect("Can't query password");
    }
}

fn main() {
    let mut opts = Options::new();
    opts.optopt("p", "db-path", "path to the database", "PATH");
    opts.optflag("S", "stdin", "read password from stdin");
    opts.optflag("h", "help", "print this help menu");

    let args: Vec<String> = env::args().collect();
    let exe = args[0].clone();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    if matches.opt_present("h") || matches.free.is_empty() {
        print_usage(&exe, opts);
        return;
    }

    unsafe {
        STDIN_PASSWORD = matches.opt_present("S");
    }

    let db_path = match matches.opt_str("p") {
        Some(p) => p,
        None => {
            match env::home_dir() {
                Some(path) => format!("{}/.pwsafe/default.psafe3", path.display()).to_string(),
                None => panic!("Can't get home directory"),
            }
        },
    };

    if !run_op(&db_path, &matches.free) {
        print_usage(&exe, opts);
    }
}
