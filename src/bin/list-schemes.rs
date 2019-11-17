fn main() {
//    let mut paths : Vec<String> = Default::default();
    use std::fs;

    let mut schemes = vec![];
    match fs::read_dir(":") {
        Ok(entries) => for entry_res in entries {
            if let Ok(entry) = entry_res {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    let scheme = path.trim_start_matches(':').trim_matches('/');
                    if scheme.starts_with("disk") {
                        println!("found scheme {}", scheme);
                        schemes.push(format!("{}:", scheme));
                    }
                }
            }
        },
        Err(err) => {
            println!("failed to list schemes: {}", err);
        }
    }

    for scheme in schemes {
        match fs::read_dir(&scheme) {
            Ok(entries) => for entry_res in entries {
                if let Ok(entry) = entry_res {
                    if let Ok(path) = entry.path().into_os_string().into_string() {
                        println!("found path {}", path);
//                        paths.push(path);
                    }
                }
            },
            Err(err) => {
                println!("failed to list '{}': {}", scheme, err);
            }
        }
    }
}