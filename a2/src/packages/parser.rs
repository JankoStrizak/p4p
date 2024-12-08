use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use regex::Regex;
use std::collections::HashMap;
use std::collections::BTreeSet;

use crate::LogFormat;
use crate::LogFormat::Linux;
use crate::LogFormat::OpenStack;
use crate::LogFormat::Spark;
use crate::LogFormat::HDFS;
use crate::LogFormat::HPC;
use crate::LogFormat::Proxifier;
use crate::LogFormat::Android;
use crate::LogFormat::HealthApp;
use std::thread;
use std::sync::mpsc;
use std::sync::Mutex;
use std::sync::Arc;
use std::collections::HashSet;
use dashmap::{DashMap, DashSet};


struct ThreadResult {
    dbl: HashMap<String, i32>,
    trpl: HashMap<String, i32>,
    arr: Vec<String>
}

pub fn format_string(lf: &LogFormat) -> String {
    match lf {
        Linux =>
            r"<Month> <Date> <Time> <Level> <Component>(\\[<PID>\\])?: <Content>".to_string(),
        OpenStack =>
            r"'<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>'".to_string(),
        Spark =>
            r"<Date> <Time> <Level> <Component>: <Content>".to_string(),
        HDFS =>
            r"<Date> <Time> <Pid> <Level> <Component>: <Content>".to_string(),
        HPC =>
            r"<LogId> <Node> <Component> <State> <Time> <Flag> <Content>".to_string(),
        Proxifier =>
            r"[<Time>] <Program> - <Content>".to_string(),
        Android =>
            r"<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>".to_string(),
        HealthApp =>
            "<Time>\\|<Component>\\|<Pid>\\|<Content>".to_string()
    }
}

pub fn censored_regexps(lf: &LogFormat) -> Vec<Regex> {
    match lf {
        Linux =>
            vec![Regex::new(r"(\d+\.){3}\d+").unwrap(),
                 Regex::new(r"\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}").unwrap(),
                 Regex::new(r"\d{2}:\d{2}:\d{2}").unwrap()],
        OpenStack =>
            vec![Regex::new(r"((\d+\.){3}\d+,?)+").unwrap(),
                 Regex::new(r"/.+?\s").unwrap()],
        // I commented out Regex::new(r"\d+").unwrap() because that censors all numbers, which may not be what we want?
        Spark =>
            vec![Regex::new(r"(\d+\.){3}\d+").unwrap(),
                 Regex::new(r"\b[KGTM]?B\b").unwrap(), 
                 Regex::new(r"([\w-]+\.){2,}[\w-]+").unwrap()],
        HDFS =>
            vec![Regex::new(r"blk_(|-)[0-9]+").unwrap(), // block id
                Regex::new(r"(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)").unwrap() // IP
                ],
        // oops, numbers require lookbehind, which rust doesn't support, sigh
        //                Regex::new(r"(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$").unwrap()]; // Numbers
        HPC =>
            vec![Regex::new(r"=\d+").unwrap()],
        Proxifier =>
            vec![Regex::new(r"<\d+\ssec").unwrap(),
                 Regex::new(r"([\w-]+\.)+[\w-]+(:\d+)?").unwrap(),
                 Regex::new(r"\d{2}:\d{2}(:\d{2})*").unwrap(),
                 Regex::new(r"[KGTM]B").unwrap()],
        Android =>
            vec![Regex::new(r"(/[\w-]+)+").unwrap(),
                 Regex::new(r"([\w-]+\.){2,}[\w-]+").unwrap(),
                 Regex::new(r"\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b").unwrap()],
        HealthApp => vec![],
    }
}

// https://doc.rust-lang.org/rust-by-example/std_misc/file/read_lines.html
// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn regex_generator_helper(format: String) -> String {
    let splitters_re = Regex::new(r"(<[^<>]+>)").unwrap();
    let spaces_re = Regex::new(r" +").unwrap();
    let brackets : &[_] = &['<', '>'];

    let mut r = String::new();
    let mut prev_end = None;
    for m in splitters_re.find_iter(&format) {
        if let Some(pe) = prev_end {
            let splitter = spaces_re.replace(&format[pe..m.start()], r"\s+");
            r.push_str(&splitter);
        }
        let header = m.as_str().trim_matches(brackets).to_string();
        r.push_str(format!("(?P<{}>.*?)", header).as_str());
        prev_end = Some(m.end());
    }
    return r;
}

pub fn regex_generator(format: String) -> Regex {
    return Regex::new(format!("^{}$", regex_generator_helper(format)).as_str()).unwrap();
}

#[test]
fn test_regex_generator_helper() {
    let linux_format = r"<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>".to_string();
    assert_eq!(regex_generator_helper(linux_format), r"(?P<Month>.*?)\s+(?P<Date>.*?)\s+(?P<Time>.*?)\s+(?P<Level>.*?)\s+(?P<Component>.*?)(\[(?P<PID>.*?)\])?:\s+(?P<Content>.*?)");

    let openstack_format = r"<Logrecord> <Date> <Time> <Pid> <Level> <Component> (\[<ADDR>\])? <Content>".to_string();
    assert_eq!(regex_generator_helper(openstack_format), r"(?P<Logrecord>.*?)\s+(?P<Date>.*?)\s+(?P<Time>.*?)\s+(?P<Pid>.*?)\s+(?P<Level>.*?)\s+(?P<Component>.*?)\s+(\[(?P<ADDR>.*?)\])?\s+(?P<Content>.*?)");
}

/// Replaces provided (domain-specific) regexps with <*> in the log_line.
fn apply_domain_specific_re(log_line: String, domain_specific_re:&Vec<Regex>) -> String {
    let mut line = format!(" {}", log_line);
    for s in domain_specific_re {
        line = s.replace_all(&line, "<*>").to_string();
    }
    return line;
}

#[test]
fn test_apply_domain_specific_re() {
    let line = "q2.34.4.5 Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; Fri Jun 17 20:55:07 2005 user unknown".to_string();
    let censored_line = apply_domain_specific_re(line, &censored_regexps(&Linux));
    assert_eq!(censored_line, " q<*> Jun 14 <*> combo sshd(pam_unix)[19937]: check pass; <*> user unknown");
}

pub fn token_splitter(log_line: String, re:&Regex, domain_specific_re:&Vec<Regex>) -> Vec<String> {
    if let Some(m) = re.captures(log_line.trim()) {
        let message = m.name("Content").unwrap().as_str().to_string();
        // println!("{}", &message);
        let line = apply_domain_specific_re(message, domain_specific_re);
        return line.trim().split_whitespace().map(|s| s.to_string()).collect();
    } else {
        return vec![];
    }
}

#[test]
fn test_token_splitter() {
    let line = "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown".to_string();
    let re = regex_generator(format_string(&Linux));
    let split_line = token_splitter(line, &re, &censored_regexps(&Linux));
    assert_eq!(split_line, vec!["check", "pass;", "user", "unknown"]);
}

// processes line, adding to the end of line the first two tokens from lookahead_line, and returns the first 2 tokens on this line
fn process_dictionary_builder_line(line: String, lookahead_line: Option<String>, regexp:&Regex, regexps:&Vec<Regex>, dbl: &mut HashMap<String, i32>, trpl: &mut HashMap<String, i32>, all_token_list: &mut Vec<String>, prev1: Option<String>, prev2: Option<String>) -> (Option<String>, Option<String>) {
    let (next1, next2) = match lookahead_line { //lookahead_line is next_line
        None => (None, None),
        Some(ll) => { //next_line
            let next_tokens = token_splitter(ll, &regexp, &regexps);
            match next_tokens.len() {
                0 => (None, None),
                1 => (Some(next_tokens[0].clone()), None),
                _ => (Some(next_tokens[0].clone()), Some(next_tokens[1].clone()))
            }
        }
    };

    let mut tokens = token_splitter(line, &regexp, &regexps);
    if tokens.is_empty() {
        return (None, None);
    }
    //add to token_list
    tokens.iter().for_each(|t| if !all_token_list.contains(t) { all_token_list.push(t.clone()) } );

    // keep this for later when we'll return it
    let last1 = match tokens.len() {
        0 => None,
        n => Some(tokens[n-1].clone())
    };
    let last2 = match tokens.len() {
        0 => None,
        1 => None,
        n => Some(tokens[n-2].clone())
    };

    let mut tokens2_ = match prev1 {
        None => tokens,
        Some(x) => { let mut t = vec![x]; t.append(&mut tokens); t}
    };
    let mut tokens2 = match next1 {
        None => tokens2_,
        Some(x) => { tokens2_.push(x); tokens2_ }
    };

    //tokens2 has the line with one previous token and one next token

    for doubles in tokens2.windows(2) {
        let double_tmp = format!("{}^{}", doubles[0], doubles[1]);
	*dbl.entry(double_tmp.to_owned()).or_default() += 1; 
    }
    /*
        if <doubles[0], doubles[1]> not in dbl => it is added to hashmap as the key, and the value becomes 1
        if <doubles[0], doubles[1]> is in dbl => it's value is incremented by 1
    */

    let mut tokens3_ = match prev2 {
        None => tokens2,
        Some(x) => { let mut t = vec![x]; t.append(&mut tokens2); t}
    };
    let tokens3 = match next2 {
        None => tokens3_,
        Some(x) => { tokens3_.push(x); tokens3_ }
    };
    for triples in tokens3.windows(3) {
        let triple_tmp = format!("{}^{}^{}", triples[0], triples[1], triples[2]);
	*trpl.entry(triple_tmp.to_owned()).or_default() += 1;
    }
    return (last1, last2); //will be used as prev1 and prev2 by the next line
}

fn process_dictionary_builder_line_crate(line: String, lookahead_line: Option<String>, regexp:&Regex, regexps:&Vec<Regex>, dbl: &DashMap<String, i32>, trpl: &DashMap<String, i32>, all_token_list: &DashSet<String>, prev1: Option<String>, prev2: Option<String>) -> (Option<String>, Option<String>) {
    let (next1, next2) = match lookahead_line { //lookahead_line is next_line
        None => (None, None),
        Some(ll) => { //next_line
            let next_tokens = token_splitter(ll, &regexp, &regexps);
            match next_tokens.len() {
                0 => (None, None),
                1 => (Some(next_tokens[0].clone()), None),
                _ => (Some(next_tokens[0].clone()), Some(next_tokens[1].clone()))
            }
        }
    };

    let mut tokens = token_splitter(line, &regexp, &regexps);
    if tokens.is_empty() {
        return (None, None);
    }
    //add to token_list
    tokens.iter().for_each(|t| if !all_token_list.contains(t) { all_token_list.insert(t.clone()); } );

    // keep this for later when we'll return it
    let last1 = match tokens.len() {
        0 => None,
        n => Some(tokens[n-1].clone())
    };
    let last2 = match tokens.len() {
        0 => None,
        1 => None,
        n => Some(tokens[n-2].clone())
    };

    let mut tokens2_ = match prev1 {
        None => tokens,
        Some(x) => { let mut t = vec![x]; t.append(&mut tokens); t}
    };
    let mut tokens2 = match next1 {
        None => tokens2_,
        Some(x) => { tokens2_.push(x); tokens2_ }
    };

    //tokens2 has the line with one previous token and one next token

    for doubles in tokens2.windows(2) {
        let double_tmp = format!("{}^{}", doubles[0], doubles[1]);
	*dbl.entry(double_tmp.to_owned()).or_default() += 1; 
    }
    /*
        if <doubles[0], doubles[1]> not in dbl => it is added to hashmap as the key, and the value becomes 1
        if <doubles[0], doubles[1]> is in dbl => it's value is incremented by 1
    */

    let mut tokens3_ = match prev2 {
        None => tokens2,
        Some(x) => { let mut t = vec![x]; t.append(&mut tokens2); t}
    };
    let tokens3 = match next2 {
        None => tokens3_,
        Some(x) => { tokens3_.push(x); tokens3_ }
    };
    for triples in tokens3.windows(3) {
        let triple_tmp = format!("{}^{}^{}", triples[0], triples[1], triples[2]);
	*trpl.entry(triple_tmp.to_owned()).or_default() += 1;
    }
    return (last1, last2); //will be used as prev1 and prev2 by the next line
}

fn dictionary_builder(raw_fn: String, format: String, regexps: Vec<Regex>, _threads: usize, is_single_map: bool) -> (HashMap<String, i32>, HashMap<String, i32>, Vec<String>) {
    let mut dbl = HashMap::new();
    let mut trpl = HashMap::new();
    let mut all_token_list = vec![];
    let regexp = regex_generator(format);
    let mut threads= _threads;

    if is_single_map {
        //create vector of vectors
        let mut total_lines = 0;
        let mut count = 0;
        if let Ok(lines) = read_lines(raw_fn.clone()) {
            let mut lp = lines.peekable();
            //count total
            loop {
                match lp.next() {
                    None => break,
                    Some(Ok(ip)) =>{
                        total_lines +=1;
                    },
                    Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
                }
            }
        }
        if total_lines < threads {threads = total_lines.clone();}
        let mut sections: Vec<Vec<String>> = vec![Vec::new(); threads];
        if let Ok(lines) = read_lines(raw_fn.clone()) {
            let mut lp = lines.peekable();
            // println!("{}",total_lines); //correct
            //section
            for _ in 0..threads{
                let start_line = (total_lines)/threads * (count);
                let line_after = if (count == (threads-1)){ 
                        None
                    }else{
                        Some((total_lines as i32)/(threads as i32) * ((count+1)as i32))
                    };

                let lines_to_take = match line_after{
                    None =>{
                        total_lines-start_line
                    },
                    Some(a)=>{
                        (a as usize)-start_line
                    }
                }; 
                //fill in section
                for _ in 0..lines_to_take {
                    match lp.next() {
                        None => break,
                        Some(Ok(ip)) =>{
                            // println!("printing ip: {}", ip);
                            sections[count as usize].push(ip.clone());
                        },
                        Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
                    }
                }
                // println!("start_line: {}, line_after: {}, lines_to_take: {}", start_line, line_after.unwrap_or(-1), lines_to_take);
                // println!("Length of the Vexc<String>: {}", sections[count].len());
                count+=1;
                
            }
            // sections[count].iter().for_each(|string| println!("{}", string));
        }
        

        let mut senders = Vec::with_capacity(threads);
        let mut receivers = Vec::with_capacity(threads);
        let mut handles = Vec::with_capacity(threads);

        //loop for sender and reciever stuff
        for _ in 0..threads {
            let (sender, receiver) = mpsc::channel();
            senders.push(sender);
            receivers.push(receiver);
        }
        let mut count = 0; //counter to know which thread this is
        for s in senders.iter(){
                let sender_clone = s.clone();    
                let regexps_clone = regexps.clone();
                let regexp_clone = regexp.clone();
                let sections_thread = sections.clone();

                //create thread
                let handle = thread::spawn(move || {
                    let (mut prev1, mut prev2) = if count == 0 {
                            (None,None)
                        }else{
                            let tokens = token_splitter(sections_thread[count-1].last().unwrap().to_string(), &regexp_clone, &regexps_clone);
                            let last1 = match tokens.len() {
                                0 => None,
                                n => Some(tokens[n-1].clone())
                            };
                            let last2 = match tokens.len() {
                                0 => None,
                                1 => None,
                                n => Some(tokens[n-2].clone())
                            };
                            (last1,last2)
                        };
                    let mut dbl_thread=HashMap::new();
                    let mut trpl_thread=HashMap::new();
                    let mut all_token_list_thread=vec![];
                    //the regualr code to copy the vibes
                    // let mut lp = section.peekable();
                    let mut lp = sections_thread[count].iter().peekable();
                    loop {
                        // println!("count: {}, prev1: {}, prev2:{}", count.to_string(), prev1.clone().unwrap_or("-1".to_string()), prev2.clone().unwrap_or("-1".to_string()));

                        match lp.next() {
                            None => {
                                break; 
                            }, //lp.next goes after last line
                            Some(ip) => //ip is the "next line" we are processing
                                match lp.peek() {
                                    None => //no next line (AKA last line)
                                        {if(count == (threads-1)as usize){
                                            (prev1, prev2) = process_dictionary_builder_line(ip.clone(), None, &regexp_clone, &regexps_clone, &mut dbl_thread, &mut trpl_thread, &mut all_token_list_thread, prev1.clone(), prev2.clone());
                                        }else{
                                            (prev1, prev2) = process_dictionary_builder_line(ip.clone(), Some((sections_thread[count+1][0]).clone()), &regexp_clone, &regexps_clone, &mut dbl_thread, &mut trpl_thread, &mut all_token_list_thread, prev1.clone(), prev2.clone());
                                            // println!("count: {}, next_line: {}",count,( sections_thread[count+1][0]).clone());
                                        }},
                                    Some(next_line) => {//not last line, next_line is the line after ip
                                        (prev1, prev2) = process_dictionary_builder_line(ip.clone(), Some(next_line.clone().to_string()), &regexp_clone, &regexps_clone, &mut dbl_thread, &mut trpl_thread, &mut all_token_list_thread, prev1.clone(), prev2.clone());
                                        // println!("count: {}, next_line: {}",count,( next_line.clone().to_string()));
                                    }
                                    // Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
                                }
                            // Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
                        }

                    }
                    let r = ThreadResult {
                        dbl: dbl_thread.clone(),
                        trpl: trpl_thread,
                        arr: all_token_list_thread
                    };
                    //add the previous
                    sender_clone.send(r).unwrap();
                    let m = "dbl_thread ".to_owned() + &count.to_string();
                    print_dict(&m, &(dbl_thread));
                });
                handles.push(handle);
                count +=1;
        }

        let results: Vec<ThreadResult> = receivers.into_iter().map(|receiver| receiver.recv().unwrap()).collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Print results
        // println!("got to before extend for loop");
        for result in results.iter() {
            for (key, value) in result.dbl.clone().iter() {
                *dbl.entry(key.to_owned()).or_default() += value; 
                // println!("dbl Key: {}, Value: {}", key, value);
            }
            for (key, value) in result.trpl.clone().iter() {
                *trpl.entry(key.to_owned()).or_default() += value;
                // println!("trpl Key: {}, Value: {}", key, value);
            }
            
            all_token_list.extend(result.arr.clone());
        }
    }else{
        let mut double_map_crate: Arc<DashMap<String, i32>> = Arc::new(DashMap::new());
        let mut triple_map_crate: Arc<DashMap<String, i32>> = Arc::new(DashMap::new());
        let mut token_list_crate: Arc<DashSet<String>> = Arc::new(DashSet::new());

        //create vector of vectors
        let mut total_lines = 0;
        let mut count = 0;
        if let Ok(lines) = read_lines(raw_fn.clone()) {
            let mut lp = lines.peekable();
            //count total
            loop {
                match lp.next() {
                    None => break,
                    Some(Ok(ip)) =>{
                        total_lines +=1;
                    },
                    Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
                }
            }
        }
        if (total_lines < threads) {threads = total_lines.clone();}
        let mut sections: Vec<Vec<String>> = vec![Vec::new(); threads];
        if let Ok(lines) = read_lines(raw_fn.clone()) {
            let mut lp = lines.peekable();
            // println!("{}",total_lines); //correct
            //section
            for _ in 0..threads{
                let start_line = (total_lines)/threads * (count);
                let line_after = if (count == (threads-1)){ 
                        None
                    }else{
                        Some((total_lines as i32)/(threads as i32) * ((count+1)as i32))
                    };

                let lines_to_take = match line_after{
                    None =>{
                        total_lines-start_line
                    },
                    Some(a)=>{
                        (a as usize)-start_line
                    }
                }; 
                //fill in section
                for _ in 0..lines_to_take {
                    match lp.next() {
                        None => break,
                        Some(Ok(ip)) =>{
                            // println!("printing ip: {}", ip);
                            sections[count as usize].push(ip.clone());
                        },
                        Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
                    }
                }
                // println!("start_line: {}, line_after: {}, lines_to_take: {}", start_line, line_after.unwrap_or(-1), lines_to_take);
                // println!("Length of the Vexc<String>: {}", sections[count].len());
                count+=1;
                
            }
            // sections[count].iter().for_each(|string| println!("{}", string));
        }

        let mut handles = Vec::with_capacity(threads);

        let mut count = 0; //counter to know which thread this is
        for _ in 0..threads{
                let regexps_clone = regexps.clone();
                let regexp_clone = regexp.clone();
                let sections_thread = sections.clone();

                let double_map_crate_thread = double_map_crate.clone();
                let triple_map_crate_thread = triple_map_crate.clone();
                let token_list_crate_thread = token_list_crate.clone();

                //create thread
                let handle = thread::spawn(move || {
                    let (mut prev1, mut prev2) = if count == 0 {
                            (None,None)
                        }else{
                            let tokens = token_splitter(sections_thread[count-1].last().unwrap().to_string(), &regexp_clone, &regexps_clone);
                            let last1 = match tokens.len() {
                                0 => None,
                                n => Some(tokens[n-1].clone())
                            };
                            let last2 = match tokens.len() {
                                0 => None,
                                1 => None,
                                n => Some(tokens[n-2].clone())
                            };
                            (last1,last2)
                        };
                    let mut lp = sections_thread[count].iter().peekable();
                    loop {
                        // println!("count: {}, prev1: {}, prev2:{}", count.to_string(), prev1.clone().unwrap_or("-1".to_string()), prev2.clone().unwrap_or("-1".to_string()));
                        match lp.next() {
                            None => {
                                break; 
                            }, //lp.next goes after last line
                            Some(ip) => //ip is the "next line" we are processing
                                match lp.peek() {
                                    None => //no next line (AKA last line)
                                        {if(count == (threads-1)as usize){
                                            (prev1, prev2) = process_dictionary_builder_line_crate(ip.clone(), None, &regexp_clone, &regexps_clone, &double_map_crate_thread, &triple_map_crate_thread, &token_list_crate_thread, prev1.clone(), prev2.clone());
                                        }else{
                                            (prev1, prev2) = process_dictionary_builder_line_crate(ip.clone(), Some((sections_thread[count+1][0]).clone()), &regexp_clone, &regexps_clone, &double_map_crate_thread, &triple_map_crate_thread, &token_list_crate_thread, prev1.clone(), prev2.clone());
                                            // println!("count: {}, next_line: {}",count,( sections_thread[count+1][0]).clone());
                                        }},
                                    Some(next_line) => {//not last line, next_line is the line after ip
                                        (prev1, prev2) = process_dictionary_builder_line_crate(ip.clone(), Some(next_line.clone().to_string()), &regexp_clone, &regexps_clone, &double_map_crate_thread, &triple_map_crate_thread, &token_list_crate_thread, prev1.clone(), prev2.clone());
                                        // println!("count: {}, next_line: {}",count,( next_line.clone().to_string()));
                                    }
                                    // Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
                                }
                            // Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
                        }

                    }
                    //add the previous
                });
                handles.push(handle);
                count +=1;
        }

        for handle in handles {
            handle.join().unwrap();
        }

        dbl = Arc::try_unwrap(double_map_crate).unwrap().into_iter().collect();
        trpl = Arc::try_unwrap(triple_map_crate).unwrap().into_iter().collect();
        all_token_list = Arc::try_unwrap(token_list_crate).unwrap().into_iter().collect();
        // Print results
        // println!("got to before extend for loop");
    }
    return (dbl, trpl, all_token_list);
}

#[test]
fn test_dictionary_builder_process_line_lookahead_is_none() {
    let line = "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown".to_string();
    let re = regex_generator(format_string(&Linux));
    let mut dbl = HashMap::new();
    let mut trpl = HashMap::new();
    let mut all_token_list = vec![];
    let (last1, last2) = process_dictionary_builder_line(line, None, &re, &censored_regexps(&Linux), &mut dbl, &mut trpl, &mut all_token_list, None, None);
    assert_eq!((last1, last2), (Some("unknown".to_string()), Some("user".to_string())));

    let mut dbl_oracle = HashMap::new();
    dbl_oracle.insert("user^unknown".to_string(), 1);
    dbl_oracle.insert("pass;^user".to_string(), 1);
    dbl_oracle.insert("check^pass;".to_string(), 1);
    assert_eq!(dbl, dbl_oracle);

    let mut trpl_oracle = HashMap::new();
    trpl_oracle.insert("pass;^user^unknown".to_string(), 1);
    trpl_oracle.insert("check^pass;^user".to_string(), 1);
    assert_eq!(trpl, trpl_oracle);
}

#[test]
fn test_dictionary_builder_process_line_lookahead_is_some() {
    let line = "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown".to_string();
    let next_line = "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: baz bad".to_string();
    let re = regex_generator(format_string(&Linux));
    let mut dbl = HashMap::new();
    let mut trpl = HashMap::new();
    let mut all_token_list = vec![];
    let (last1, last2) = process_dictionary_builder_line(line, Some(next_line), &re, &censored_regexps(&Linux), &mut dbl, &mut trpl, &mut all_token_list, Some("foo".to_string()), Some("bar".to_string()));
    assert_eq!((last1, last2), (Some("unknown".to_string()), Some("user".to_string())));

    let mut dbl_oracle = HashMap::new();
    dbl_oracle.insert("unknown^baz".to_string(), 1);
    dbl_oracle.insert("foo^check".to_string(), 1);
    dbl_oracle.insert("user^unknown".to_string(), 1);
    dbl_oracle.insert("pass;^user".to_string(), 1);
    dbl_oracle.insert("check^pass;".to_string(), 1);
    assert_eq!(dbl, dbl_oracle);

    let mut trpl_oracle = HashMap::new();
    trpl_oracle.insert("pass;^user^unknown".to_string(), 1);
    trpl_oracle.insert("check^pass;^user".to_string(), 1);
    trpl_oracle.insert("unknown^baz^bad".to_string(), 1);
    trpl_oracle.insert("foo^check^pass;".to_string(), 1);
    trpl_oracle.insert("bar^foo^check".to_string(), 1);
    trpl_oracle.insert("user^unknown^baz".to_string(), 1);
    assert_eq!(trpl, trpl_oracle);
}

pub fn parse_raw(raw_fn: String, lf:&LogFormat, threads: usize, is_single_map: bool) -> (HashMap<String, i32>, HashMap<String, i32>, Vec<String>) {
    
    let (double_dict, triple_dict, all_token_list) = dictionary_builder(raw_fn, format_string(&lf), censored_regexps(&lf), threads, is_single_map);
    //remove dublicates
    let unique_set: HashSet<String> = all_token_list.into_iter().collect();
    let all_token_list_unique: Vec<String> = unique_set.into_iter().collect();
    println!("double dictionary list len {}, triple {}, all tokens {}", double_dict.len(), triple_dict.len(), all_token_list_unique.len());
    return (double_dict, triple_dict, all_token_list_unique);
}

#[test]
fn test_parse_raw_linux() {
    let (double_dict, triple_dict, mut all_token_list) = parse_raw("data/from_paper.log".to_string(), &Linux, 10, false);
    let mut all_token_list_oracle = vec![
        "hdfs://hostname/2kSOSP.log:21876+7292".to_string(),
        "hdfs://hostname/2kSOSP.log:14584+7292".to_string(),
        "hdfs://hostname/2kSOSP.log:0+7292".to_string(),
        "hdfs://hostname/2kSOSP.log:7292+7292".to_string(),
        "hdfs://hostname/2kSOSP.log:29168+7292".to_string()
    ];
    all_token_list.sort();
    all_token_list_oracle.sort();
    assert_eq!(all_token_list, all_token_list_oracle);
    let mut double_dict_oracle = HashMap::new();
    double_dict_oracle.insert("hdfs://hostname/2kSOSP.log:14584+7292^hdfs://hostname/2kSOSP.log:0+7292".to_string(), 2);
    double_dict_oracle.insert("hdfs://hostname/2kSOSP.log:21876+7292^hdfs://hostname/2kSOSP.log:14584+7292".to_string(), 2);
    double_dict_oracle.insert("hdfs://hostname/2kSOSP.log:7292+7292^hdfs://hostname/2kSOSP.log:29168+7292".to_string(), 2);
    double_dict_oracle.insert("hdfs://hostname/2kSOSP.log:0+7292^hdfs://hostname/2kSOSP.log:7292+7292".to_string(), 2);
    assert_eq!(double_dict, double_dict_oracle);
    let mut triple_dict_oracle = HashMap::new();
    triple_dict_oracle.insert("hdfs://hostname/2kSOSP.log:0+7292^hdfs://hostname/2kSOSP.log:7292+7292^hdfs://hostname/2kSOSP.log:29168+7292".to_string(), 1);
    triple_dict_oracle.insert("hdfs://hostname/2kSOSP.log:14584+7292^hdfs://hostname/2kSOSP.log:0+7292^hdfs://hostname/2kSOSP.log:7292+7292".to_string(), 1);
    triple_dict_oracle.insert("hdfs://hostname/2kSOSP.log:21876+7292^hdfs://hostname/2kSOSP.log:14584+7292^hdfs://hostname/2kSOSP.log:0+7292".to_string(), 1);
    assert_eq!(triple_dict, triple_dict_oracle);
}

/// standard mapreduce invert map: given {<k1, v1>, <k2, v2>, <k3, v1>}, returns ([v1, v2] (sorted), {<v1, [k1, k3]>, <v2, [k2]>})
pub fn reverse_dict(d: &HashMap<String, i32>) -> (BTreeSet<i32>, HashMap<i32, Vec<String>>) {
    let mut reverse_d: HashMap<i32, Vec<String>> = HashMap::new();
    let mut val_set: BTreeSet<i32> = BTreeSet::new();

    for (key, val) in d.iter() {
        if reverse_d.contains_key(val) {
            let existing_keys = reverse_d.get_mut(val).unwrap();
            existing_keys.push(key.to_string());
        } else {
            reverse_d.insert(*val, vec![key.to_string()]);
            val_set.insert(*val);
        }
    }
    return (val_set, reverse_d);
}

pub fn print_dict(s: &str, d: &HashMap<String, i32>) {
    let (val_set, reverse_d) = reverse_dict(d);

    println!("printing dict: {}", s);
    for val in &val_set {
        println!("{}: {:?}", val, reverse_d.get(val).unwrap());
    }
    println!("---");
}
