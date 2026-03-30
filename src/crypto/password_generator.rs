use rand::Rng;

/// Configuration for password generation.
#[derive(Debug, Clone)]
pub struct PasswordOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`";
const AMBIGUOUS: &str = "0OIl1";

/// Generate a random password with the given options.
pub fn generate_password(options: &PasswordOptions) -> String {
    let mut charset = String::new();

    if options.lowercase {
        charset.push_str(LOWERCASE);
    }
    if options.uppercase {
        charset.push_str(UPPERCASE);
    }
    if options.numbers {
        charset.push_str(NUMBERS);
    }
    if options.symbols {
        charset.push_str(SYMBOLS);
    }

    if charset.is_empty() {
        charset.push_str(LOWERCASE);
        charset.push_str(NUMBERS);
    }

    if options.exclude_ambiguous {
        charset = charset.chars().filter(|c| !AMBIGUOUS.contains(*c)).collect();
    }

    let charset_bytes: Vec<char> = charset.chars().collect();
    let mut rng = rand::thread_rng();

    (0..options.length)
        .map(|_| charset_bytes[rng.gen_range(0..charset_bytes.len())])
        .collect()
}

/// Configuration for passphrase generation.
#[derive(Debug, Clone)]
pub struct PassphraseOptions {
    pub num_words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            num_words: 5,
            separator: "-".to_string(),
            capitalize: true,
            include_number: true,
        }
    }
}

/// A small built-in word list for passphrase generation (EFF short list subset).
const WORD_LIST: &[&str] = &[
    "abandon", "ability", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "acid", "acoustic", "acquire", "across", "action", "actor",
    "adapt", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic",
    "afford", "agenda", "agree", "ahead", "alarm", "album", "alert", "alien",
    "alpha", "anchor", "anger", "angle", "annual", "answer", "antenna", "anxiety",
    "apart", "apology", "apple", "april", "arctic", "arena", "armor", "army",
    "arrow", "artist", "asset", "atom", "auction", "audit", "august", "aunt",
    "aware", "balance", "bamboo", "banner", "barrel", "basket", "battle", "beach",
    "beauty", "begin", "below", "bench", "benefit", "bicycle", "blade", "blanket",
    "blast", "bleak", "blind", "blood", "blossom", "board", "bonus", "border",
    "bounce", "brain", "brand", "brave", "bread", "bridge", "brisk", "broken",
    "bronze", "brush", "bubble", "budget", "buffalo", "bundle", "burden", "burst",
    "cabin", "cable", "cactus", "camera", "campus", "canal", "canvas", "capital",
    "carbon", "cargo", "carpet", "casino", "castle", "catalog", "catch", "cattle",
    "cause", "celery", "cement", "census", "cereal", "change", "chapter", "charge",
    "cherry", "chicken", "chief", "choice", "church", "circle", "citizen", "claim",
    "clarify", "clerk", "clever", "clinic", "clock", "cluster", "coach", "coconut",
    "coffee", "coil", "collect", "column", "combine", "comfort", "common", "company",
    "concert", "conduct", "confirm", "congress", "connect", "control", "convert",
    "cookie", "copper", "coral", "corner", "correct", "cottage", "cotton", "couch",
    "country", "couple", "course", "cousin", "cover", "craft", "credit", "crisis",
    "cross", "crowd", "cruel", "cruise", "crystal", "culture", "cupboard", "curtain",
    "cycle", "damage", "danger", "daring", "debate", "decade", "decline", "defense",
    "degree", "delay", "deliver", "demand", "denial", "dentist", "depart", "depend",
    "deputy", "derive", "desert", "design", "detail", "detect", "develop", "device",
    "devote", "diagram", "diamond", "diary", "diesel", "differ", "digital", "dignity",
    "dilemma", "dinner", "direct", "discuss", "display", "distance", "doctor", "dolphin",
    "domain", "donate", "donkey", "dragon", "drama", "drastic", "dream", "dress",
    "drift", "drink", "drive", "dryer", "duck", "dumb", "dune", "during",
    "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily",
    "economy", "editor", "effort", "eight", "either", "elbow", "elder", "electric",
    "elegant", "element", "elite", "embark", "embody", "embrace", "emerge", "emotion",
    "employ", "enable", "endorse", "enemy", "energy", "engine", "enjoy", "enrich",
    "ensure", "enter", "entire", "entry", "episode", "equal", "equip", "erode",
    "erosion", "escape", "essay", "essence", "estate", "eternal", "evoke", "exact",
    "example", "excess", "excite", "exclude", "execute", "exhaust", "exhibit", "exile",
    "expand", "expect", "expire", "explain", "express", "extend", "extra", "eyebrow",
];

/// Generate a random passphrase.
pub fn generate_passphrase(options: &PassphraseOptions) -> String {
    let mut rng = rand::thread_rng();

    let words: Vec<String> = (0..options.num_words)
        .map(|_| {
            let word = WORD_LIST[rng.gen_range(0..WORD_LIST.len())].to_string();
            if options.capitalize {
                let mut chars = word.chars();
                match chars.next() {
                    None => String::new(),
                    Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                }
            } else {
                word
            }
        })
        .collect();

    let mut passphrase = words.join(&options.separator);

    if options.include_number {
        let num: u16 = rng.gen_range(0..1000);
        passphrase = format!("{}{}{}", passphrase, options.separator, num);
    }

    passphrase
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_default() {
        let password = generate_password(&PasswordOptions::default());
        assert_eq!(password.len(), 20);
    }

    #[test]
    fn test_generate_password_custom() {
        let opts = PasswordOptions {
            length: 32,
            uppercase: true,
            lowercase: true,
            numbers: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let password = generate_password(&opts);
        assert_eq!(password.len(), 32);
        assert!(password.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn test_generate_passphrase() {
        let passphrase = generate_passphrase(&PassphraseOptions::default());
        let parts: Vec<&str> = passphrase.split('-').collect();
        // 5 words + 1 number = 6 parts
        assert_eq!(parts.len(), 6);
    }
}
